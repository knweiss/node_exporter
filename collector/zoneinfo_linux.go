// Copyright 2017 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//
// This is an incomplete but functional implementation of a 'zoneinfo'
// collector (Linux).
//
// '/proc/zoneinfo' is a proc file of the Linux kernel that contains lots of
// useful NUMA node and memory zone metrics of the virtual memory subsystem.
//
// This collector was tested on RHEL/CentOS 6 and 7 only.
//
// TODO: Port to https://github.com/prometheus/procfs
// TODO: Parse all fields/metrics available in /proc/zoneinfo.
// TODO: Support all historic variants of the /proc/zoneinfo file format.

// +build !nozoneinfo

package collector

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	zoneInfoSubsystem = "zoneinfo"
)

var (
	nodeZoneRE  = regexp.MustCompile(`Node (\d+), zone\s+(\w+)`)
	zoneInfoMap = map[string]zoneInfoLineDesc{
		"nr_free_pages": {
			metricName: "free_pages",
			metricDesc: "Number of free pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"min": {
			metricName: "min_pages",
			metricDesc: "The min watermark of this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"low": {
			metricName: "low_pages",
			metricDesc: "The low watermark of this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"high": {
			metricName: "high_pages",
			metricDesc: "The high watermark of this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"scanned": {
			metricName: "scanned_pages",
			metricDesc: "Number of scanned pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"spanned": {
			metricName: "spanned_pages",
			metricDesc: "Number of spanned pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"present": {
			metricName: "present_pages",
			metricDesc: "Number of present pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"managed": {
			metricName: "managed_pages",
			metricDesc: "Number of managed pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		// anonymous pages
		"nr_active_anon": {
			metricName: "active_anon_pages",
			metricDesc: "Number of active anonymous pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_inactive_anon": {
			metricName: "inactive_anon_pages",
			metricDesc: "Number of inactive anonymous pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_isolated_anon": {
			metricName: "isolated_anon_pages",
			metricDesc: "Number of temporarily isolated pages from anonymous pages LRU in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_anon_pages": {
			metricName: "anon_pages",
			metricDesc: "Number of anonymous pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		// special-case: transparent hugepages
		"nr_anon_transparent_hugepages": {
			metricName: "anon_transparent_hugepages",
			metricDesc: "Number of anonymous transparent_hugepages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		// file pages
		"nr_active_file": {
			metricName: "active_file_pages",
			metricDesc: "Number of active pages with file-backing in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_inactive_file": {
			metricName: "inactive_file_pages",
			metricDesc: "Number of inactive pages with file-backing in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_isolated_file": {
			metricName: "isolated_file_pages",
			metricDesc: "Number of temporarily isolated pages from file-backing pages LRU in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_file_pages": {
			metricName: "file_pages",
			metricDesc: "Number of pages with file-backing in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		// slab
		"nr_slab_reclaimable": {
			metricName: "reclaimable_slab_pages",
			metricDesc: "Number of reclaimable slab pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_slab_unreclaimable": {
			metricName: "unreclaimable_slab_pages",
			metricDesc: "Number of unreclaimable slab pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		// various
		"nr_mlock_stack": {
			metricName: "mlock_pages",
			metricDesc: "Number of mlock()ed pages found and moved off LRU in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_kernel_stack": {
			metricName: "kernel_stack_pages",
			metricDesc: "Number of kernel stack pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_mapped": {
			metricName: "mapped_pages",
			metricDesc: "Number of mapped pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_dirty": {
			metricName: "dirty_pages",
			metricDesc: "Number of dirty pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_writeback": {
			metricName: "writeback_pages",
			metricDesc: "Number of writeback pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_unevictable": {
			metricName: "unevictable_pages",
			metricDesc: "Number of unevictable pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		"nr_shmem": {
			metricName: "shmem_pages",
			metricDesc: "Number of shmem pages in this node and zone",
			metricType: prometheus.GaugeValue,
			valueField: 1,
		},
		// counters
		"nr_dirtied": {
			metricName: "dirtied_pages_total",
			metricDesc: "Number of dirtied pages since boot",
			metricType: prometheus.CounterValue,
			valueField: 1,
		},
		"nr_written": {
			metricName: "written_pages_total",
			metricDesc: "Number of written pages since boot",
			metricType: prometheus.CounterValue,
			valueField: 1,
		},
		// NUMA counters
		// TODO: Improve descriptions
		"numa_hit": {
			metricName: "numa_hit_total",
			metricDesc: "Number of NUMA hit allocations in this node and zone since boot",
			metricType: prometheus.CounterValue,
			valueField: 1,
		},
		"numa_miss": {
			metricName: "numa_miss_total",
			metricDesc: "Number of NUMA miss allocations in this node and zone since boot",
			metricType: prometheus.CounterValue,
			valueField: 1,
		},
		"numa_foreign": {
			metricName: "numa_foreign_total",
			metricDesc: "Number of NUMA foreign allocations in this node and zone since boot",
			metricType: prometheus.CounterValue,
			valueField: 1,
		},
		"numa_interleave": {
			metricName: "numa_interleave_total",
			metricDesc: "Number of NUMA interleave allocations in this node and zone since boot",
			metricType: prometheus.CounterValue,
			valueField: 1,
		},
		"numa_local": {
			metricName: "numa_local_total",
			metricDesc: "Number of NUMA local allocations in this node and zone since boot",
			metricType: prometheus.CounterValue,
			valueField: 1,
		},
		"numa_other": {
			metricName: "numa_other_total",
			metricDesc: "Number of NUMA other allocations in this node and zone since boot",
			metricType: prometheus.CounterValue,
			valueField: 1,
		},
	}

	// errors
	errCantParse = errors.New("can't parse /proc/zoneinfo")
)

type zoneInfoCollector struct{}

// zoneInfoLineDesc describes the metric infos of a line in /proc/zoneinfo.
type zoneInfoLineDesc struct {
	metricName string
	metricDesc string
	metricType prometheus.ValueType
	valueField int
	// type
}

func init() {
	registerCollector("zoneinfo", defaultEnabled, NewZoneInfoCollector)
}

// NewZoneInfoCollector returns a new Collector exposing zoneinfo stats.
func NewZoneInfoCollector() (Collector, error) {
	return &zoneInfoCollector{}, nil
}

// # cat /proc/zoneinfo |grep ^Node -A 9
// Node 0, zone      DMA
//   per-node stats                 \
//       nr_inactive_anon 72251      \ optional
//       ...                         /
//       nr_active_anon 61316       /
//   pages free     3965
//         min      3
//         low      3
//         high     4
//         scanned  0
//         spanned  4095
//         present  3990
//         managed  3969
//     nr_free_pages 3965
// --
// Node 0, zone    DMA32
//   pages free     46089
//         min      654
//         low      817
//         high     981
//         scanned  0
//         spanned  1044480
//         present  780160
//         managed  717695
//     nr_free_pages 46089
// --
// Node 0, zone   Normal
//   pages free     241793
//         min      10576
//         low      13220
//         high     15864
//         scanned  0
//         spanned  11796480
//         present  11796480
//         managed  11599355
//     nr_free_pages 241793
// --
// Node 1, zone   Normal
//   pages free     34688
//         min      11293
//         low      14116
//         high     16939
//         scanned  0
//         spanned  12582912
//         present  12582912
//         managed  12385727
//     nr_free_pages 34688

func (c *zoneInfoCollector) Update(ch chan<- prometheus.Metric) error {
	file, err := os.Open(procFilePath("zoneinfo"))
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	node := "Unknown"
	zone := "Unknown"
	perNodeStat := false
	for scanner.Scan() {
		var value float64
		var err error
		line := strings.TrimSpace(scanner.Text())
		if nodeZone := nodeZoneRE.FindStringSubmatch(line); nodeZone != nil {
			node = nodeZone[1]
			zone = nodeZone[2]
			continue
		}
		if strings.HasPrefix(line, "per-node stats") {
			perNodeStat = true
			continue
		}
		if strings.HasPrefix(line, "pages free") {
			perNodeStat = false
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		ld, found := zoneInfoMap[parts[0]]
		if !found {
			continue
		}
		metric := ld.metricName
		desc := ld.metricDesc
		if value, err = strconv.ParseFloat(parts[ld.valueField], 64); err != nil {
			return fmt.Errorf("can't parse /proc/zoneinfo: %s", err)
		}
		if perNodeStat {
			// per-node metric
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, zoneInfoSubsystem, metric),
					desc,
					[]string{"node"}, nil,
				),
				ld.metricType,
				value,
				node,
			)
		} else {
			// node and zone metric
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, zoneInfoSubsystem, metric),
					desc,
					[]string{"node", "zone"}, nil,
				),
				ld.metricType,
				value,
				node,
				zone,
			)
		}
	}
	if node == "Unknown" {
		return errCantParse
	}
	return scanner.Err()
}
