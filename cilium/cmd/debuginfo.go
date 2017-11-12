// Copyright 2017 Authors of Cilium
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

package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/common"
	pkg "github.com/cilium/cilium/pkg/client"

	"github.com/spf13/cobra"
)

var debuginfoCmd = &cobra.Command{
	Use:   "debuginfo",
	Short: "Request available debugging information from agent",
	Run:   runDebugInfo,
}

var file string

func init() {
	rootCmd.AddCommand(debuginfoCmd)
	debuginfoCmd.Flags().StringVarP(&file, "file", "f", "", "Redirect output to file")
}

func runDebugInfo(cmd *cobra.Command, args []string) {
	// Required for the BPF commands
	common.RequireRootPrivilege("cilium debuginfo")

	resp, err := client.Daemon.GetDebuginfo(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", pkg.Hint(err))
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	if len(file) > 0 {
		f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create file %s", file)
		}
		w = tabwriter.NewWriter(f, 5, 0, 3, ' ', 0)
	}
	p := resp.Payload
	fmt.Fprintf(w, "# Cilium debug information\n")

	printMD(w, "Cilium version", p.CiliumVersion)
	printMD(w, "Kernel version", p.KernelVersion)

	printMD(w, "Cilium status", "")
	printTicks(w)
	pkg.FormatStatusResponse(w, p.CiliumStatus)
	printTicks(w)

	printMD(w, "Cilium environment keys", strings.Join(p.EnvironmentVariables, "\n"))

	printMD(w, "Endpoint list", "")
	printTicks(w)
	printEndpointList(w, p.EndpointList)
	printTicks(w)

	for _, ep := range p.EndpointList {
		epID := strconv.FormatInt(ep.ID, 10)
		printList(w, "BPF Endpoint List "+epID, "bpf", "endpoint", "list", epID)
		printList(w, "BPF Policy List "+epID, "bpf", "policy", "list", epID)
		printList(w, "BPF CT List "+epID, "bpf", "ct", "list", epID)
		printList(w, "BPF LB List "+epID, "bpf", "lb", "list", epID)
		printList(w, "BPF Tunnel List "+epID, "bpf", "tunnel", "list", epID)
		printList(w, "Endpoint Get "+epID, "endpoint", "get", epID)

		if ep.Identity != nil {
			id := strconv.FormatInt(ep.Identity.ID, 10)
			printList(w, "Identity get "+id, "identity", "get", id)
		}
	}

	printMD(w, "Service list", "")
	printTicks(w)
	printServiceList(w, p.ServiceList)
	printTicks(w)

	printMD(w, "Policy get", fmt.Sprintf(":\n %s\nRevision: %d\n", p.Policy.Policy, p.Policy.Revision))
	printMD(w, "Cilium memory map\n", p.CiliumMemoryMap)
	if nm := p.CiliumNodemonitorMemoryMap; len(nm) > 0 {
		printMD(w, "Cilium nodemonitor memory map", p.CiliumNodemonitorMemoryMap)
	}
}

func printList(w io.Writer, header string, args ...string) {
	output, err := exec.Command("cilium", args...).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while reading '%s', %s\n", args, err)
	}
	printMD(w, header, string(output))
}

func printMD(w io.Writer, header string, body string) {
	if len(body) > 0 {
		fmt.Fprintf(w, "\n#### %s\n\n```\n%s\n```\n\n", header, body)
	} else {
		fmt.Fprintf(w, "\n#### %s\n\n", header)
	}
}

func printTicks(w io.Writer) {
	fmt.Fprint(w, "```\n")
}
