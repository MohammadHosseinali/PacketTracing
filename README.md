# Tracing a packet using EASE analysis
Visualizing Different network states during a TCP connection using EASE scripting

# Introduction
This project aims to provide a comprehensive visualization of TCP connection states from the Linux Kernel perspective using TraceCompass and EASE scripting. By analyzing Linux Kernel events related to TCP connections, we gain valuable insights into the inner workings of the connections. To achieve this, we establish a TCP connection to www.example.com using the curl command from the Linux terminal. Simultaneously, we trace the relevant Linux Kernel events using LTTng and a customized bash script.

# Trace Collection
To collect the necessary traces, we execute the following steps:
1. Start the LTTng session daemon with the command "lttng-sessiond."
2. Create a new LTTng session.
3. Enable all system call events using the command "lttng enable-event -k --syscall --all."
4. Enable specific kernel events related to scheduling, interrupts, networking, and socket buffer using the command "lttng enable-event -k sched_switch, sched_wak'*, irq_*, net_*, skb_*".
5. Add essential context information such as vtid, vpid, and procname using the command "lttng add-context -k -t vtid -t vpid -t procname".
6. Start the LTTng tracing.
7. Wait for 20 seconds to capture sufficient trace data.
8. Stop the LTTng tracing.
9. Destroy the LTTng session.

# Trace Analysis
The resulting LTTng trace file can be effectively analyzed using TraceCompass. After careful examination of the trace file and analyzing the traced Kernel events based on their timestamps and contents in TraceCompass, we successfully identified the events directly associated with the various states of a TCP connection. We further validated our interpretation of these events using Wireshark.

# EASE Script for Automation and Visualization
To automate the analysis process and visualize the TCP connection states, we developed an EASE script in Javascript. This script leverages TraceCompass's capabilities and emulates the default view options available in TraceCompass. By executing the EASE script, users can obtain a graphical representation of TCP connection states in a clear and concise manner.
We used these 4 stages to visualize a TCP connection: 

1. DNS
2. Handshake
3. Data Transmission (Send or Receive)
4. Connection close

![An output example for command curl](https://github.com/Mohammad-h78/PacketTracing/blob/main/Results/ease_screenshot.png?raw=true)

# How to Run
1. Download the Javascript code and add it to Trace-compass. 
2. Right click on the code and select Run Configuration.
3. Set Execution Engine to Rhino and Enter a specific process name in script arguments (We used curl for instance).

# Challenges and Future Enhancements
Throughout this project, we encountered several challenges, such as determining the specific Kernel functions responsible for handling TCP connections by inspecting the Linux Kernel code. Additionally, we had to thoroughly examine all processes beyond the scope of the curl process to identify any potential connections or dependencies. 

While the current visualization provides a basic representation of a TCP connection established through the curl command, our goal is to expand the tool's functionality. Future enhancements involve generalizing the analysis tool to support any TCP connection, not just those established via curl. Moreover, we aim to incorporate additional details, such as event names and network layer information, to provide a more comprehensive understanding of the connection states. Achieving these objectives would require the implementation of appropriate kprobes and a deeper exploration of the extensive Kernel codebase.
