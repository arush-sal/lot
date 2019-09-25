# LOT (Linux observability Tool : Lots of Tools)

## Motivation

LoT is planned to be a command line utility that provides across the board logging and debugging options for processes and containers so that those can be assessed using a single entry and access point.

The idea in LoT (linux observability tools/lots of tools) is to aggregate existing functionalities to provide a single point of access to human debuggers. This should also be integratable in pipelines to provide relevant and (if specified actionable) information. In its whole the underlying tools and the work around them are inspired from awesome summarized Linux tools charts from [Brendan Gregg](http://brendangregg.com).

## Getting LoT for your system

LoT is currently unreleased and needs to be built from the source to be used.

### Building LoT

Follow the steps below to build LoT on your machine.

#### Clone the repository.

```bash
git clone https://github.com/arush-sal/lot.git
```

#### Change directory to lot and run `make release-test`

```bash
cd lot; make release-test 
```

#### Move the newly created binary to path

```bash
sudo cp ./dist/lot_linux_amd64/lot /usr/local/bin/
```

LoT is now ready to be used.

## Usage

### Process

Running the command below should bring up the dashboard for processes.
```bash
$ lot process
```

To list the processes, process list command can be run as follows.

```bash
$ lot process list
```

To fetch the information about top processes, the top command can be run as,

```bash
$ lot process top
```

### Network

Running the trace command returns hop by hop path to the destination address. The example is as follows,

```bash
$ lot network trace 8.8.8.8
```

To get the information about the Public IP and the private IP addresses of the current machine along with the interface details, simply run network ip as follows.

```bash
$ lot network ip
```

## References

[Linux perf tools](http://www.brendangregg.com/Perf/linux_perf_tools_full.png)

[Linux observability tools](http://www.brendangregg.com/Perf/linux_observability_tools.png)

[New tools developed for the uppcoming book](http://brendangregg.com/BPF/bpf_performance_tools_book.png)

A better breakdown and categorization of the tools are as following:

[Linux Static Performance tools](http://brendangregg.com/Perf/linux_static_tools.png)

[Linux Performance benchamarking tools](http://brendangregg.com/Perf/linux_benchmarking_tools.png)

[Observability through Sar](http://brendangregg.com/Perf/linux_observability_sar.png)

[Linux Performance Observability tools](http://brendangregg.com/Perf/perf-tools_2016.png)

[BPF Tracing tools](http://brendangregg.com/Perf/bcc_tracing_tools.png)

Maybe in future for tuning support we can consider [these](http://brendangregg.com/Perf/linux_tuning_tools.png) also.
