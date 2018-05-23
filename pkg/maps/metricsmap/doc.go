// Copyright 2018Authors of Cilium
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

// Package metricsmap represents the BPF metrics map in the BPF programs. It is
// implemented as a hash table containing an entry of different drop reasons and
// directions. The drop reason 0 is for forwarded packets while a non-zero value
// corresponds to DROP*_ reasons -(DROP_*) defined in bpf/lib/common.h
// The value is the number of packets as well as number of bytes forwarded or
// dropped.
package metricsmap
