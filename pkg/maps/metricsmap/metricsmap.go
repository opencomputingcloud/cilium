// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metricsmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var log = logging.DefaultLogger

const (
	// MapName for metrics map.
	MapName = "cilium_metrics"
	// MaxEntries is the maximum number of keys that can be present in the
	// Metrics Map.
	MaxEntries = 65536
)

// direction is the metrics direction i.e ingress (to an endpoint)
// or egress (from an endpoint).
var direction = map[uint8]string{
	1: "INGRESS",
	2: "EGRESS",
}

// dropForwardReason can be 0 for forwarded or non-zero which specifies
// the BPF drop reason
var dropForwardReason = map[uint8]string{
	0:   "FORWARD",
	130: "DROP_INVALID_SMAC",
	131: "DROP_INVALID_DMAC",
	132: "DROP_INVALID_SIP",
	133: "DROP_POLICY",
	134: "DROP_INVALID",
	135: "DROP_CT_INVALID_HDR",
	136: "DROP_CT_MISSING_ACK",
	137: "DROP_CT_UNKNOWN_PROTO",
	138: "DROP_CT_CANT_CREATE",
	139: "DROP_UNKNOWN_L3",
	140: "DROP_MISSED_TAIL_CALL",
	141: "DROP_WRITE_ERROR",
	142: "DROP_UNKNOWN_L4",
	143: "DROP_UNKNOWN_ICMP_CODE",
	144: "DROP_UNKNOWN_ICMP_TYPE",
	145: "DROP_UNKNOWN_ICMP6_CODE",
	146: "DROP_UNKNOWN_ICMP6_TYPE",
	147: "DROP_NO_TUNNEL_KEY",
	148: "DROP_NO_TUNNEL_OPT",
	149: "DROP_INVALID_GENEVE",
	150: "DROP_UNKNOWN_TARGET",
	151: "DROP_NON_LOCAL",
	152: "DROP_NO_LXC",
	153: "DROP_CSUM_L3",
	154: "DROP_CSUM_L4",
	155: "DROP_CT_CREATE_FAILED",
	156: "DROP_INVALID_EXTHDR",
	157: "DROP_FRAG_NOSUPPORT",
	158: "DROP_NO_SERVICE",
	159: "DROP_POLICY_L4",
	160: "DROP_NO_TUNNEL_ENDPOINT",
	161: "DROP_PROXYMAP_CREATE_FAILED",
	162: "DROP_POLICY_CIDR",
}

// Key must be in sync with struct metrics_key in <bpf/lib/common.h>
type Key struct {
	Reason uint8
	Dir    uint8
	Pad1   uint16
	Pad2   uint32
}

// Value must be in sync with struct metrics_value in <bpf/lib/common.h>
type Value struct {
	Count uint64
	Bytes uint64
}

// String converts the key into a human readable string format
func (k *Key) String() string {
	return fmt.Sprintf("reason:%d dir:%d", k.Reason, k.Dir)
}

// GetDirection gets the direction in human readable string format
func (k *Key) GetDirection() string {
	return dropForwardReason[k.Dir]
}

// GetReason gets the forwarded/dropped reason in human readable string format
func (k *Key) GetReason() string {
	return dropForwardReason[k.Reason]
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// String converts the value into a human readable string format
func (v *Value) String() string {
	return fmt.Sprintf("count:%d bytes:%d", v.Count, v.Bytes)
}

// GetCount returns the drop/forward count in a human readable string format
func (v *Value) GetCount() string {
	return fmt.Sprintf("%d", v.Count)
}

// GetBytes returns drop/forward bytes in a human readable string format
func (v *Value) GetBytes() string {
	return fmt.Sprintf("%d", v.Bytes)
}

// IsDrop checks if the reason is drop or not.
func (k *Key) IsDrop() bool {
	return k.Reason != 0
}

// GetCountFloat converts the request count to float
func (v *Value) GetCountFloat() float64 {
	return float64(v.Count)
}

// GetCountFloat converts the request bytes to float
func (v *Value) GetBytesFloat() float64 {
	return float64(v.Bytes)
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *Key) NewValue() bpf.MapValue { return &Value{} }

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

var (
	// Metrics is a mapping of all packet drops and forwards associated with
	// the node on ingress/egress direction
	Metrics = bpf.NewMap(
		MapName,
		bpf.BPF_MAP_TYPE_HASH,
		int(unsafe.Sizeof(Value{})),
		int(unsafe.Sizeof(Value{})),
		MaxEntries,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := Key{}, Value{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}
			return &k, &v, nil
		})
)

// updatePrometheusMetrics checks every key value pair
// and determines which promethues metrics along with respective labels
// need to be updated.
func updatePrometheusMetrics(key *Key, val *Value) {
	fmt.Println("MB in updatePrometheusMetrics key:", key.String())
	fmt.Println("MB in updatePrometheusMetrics value:", val.String())
	if key.IsDrop() {
		// Update the drop counts
		metrics.DropCountPerDirection.WithLabelValues(key.GetDirection()).Add(val.GetCountFloat())
		metrics.DropBytesPerDirection.WithLabelValues(key.GetDirection()).Add(val.GetBytesFloat())

		// Update the drop bytes
		metrics.DropCountPerReason.WithLabelValues(key.GetReason()).Add(val.GetCountFloat())
		metrics.DropBytesPerReason.WithLabelValues(key.GetReason()).Add(val.GetBytesFloat())
	} else {
		// Update the forward counts
		metrics.ForwardCountPerDirection.WithLabelValues(key.GetDirection()).Add(val.GetCountFloat())
	}

}

// SyncMetricsMap is called periodically to sync of the metrics map by
// aggregating it into drops (by drop reason), drops (by direction) and
// forwards (by direction) with the prometheus server.
func SyncMetricsMap() error {

	fmt.Println("MB in SyncMetricsMap")
	var file string = bpf.MapPath(MapName)
	metricsmap, err := bpf.OpenMap(file)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, file).Warn("Unable to open map")
		fmt.Println("MB in SyncMetricsMap Unable to open map")
		return fmt.Errorf("Unable to open metrics map: %s", err)
	}
	fmt.Println("MB in SyncMetricsMap SUCCESS with fd: ", metricsmap.GetFd())
	defer metricsmap.Close()

	var key, nextKey Key
	for {
		err := metricsmap.GetNextKey(&key, &nextKey)
		if err != nil {
			break
		}

		entry, err := metricsmap.Lookup(&nextKey)
		if err != nil {
			fmt.Println("MB in SyncMetricsMap Unable to lookup metrics map")
			return fmt.Errorf("Unable to lookup metrics map: %s", err)
		} else {
			fmt.Println("MB in SyncMetricsMap lookup metrics map SUCCESS")
			fmt.Println("MB in SyncMetricsMap key:", nextKey.String())
			fmt.Println("MB in SyncMetricsMap value:", entry.String())
		}
		value := entry.(*Value)
		// Increment Prometheus metrics here.
		updatePrometheusMetrics(&nextKey, value)
		key = nextKey
	}

	return nil
}

func init() {
	err := bpf.OpenAfterMount(Metrics)
	if err != nil {
		log.WithError(err).Error("unable to open metrics map")
	}
}
