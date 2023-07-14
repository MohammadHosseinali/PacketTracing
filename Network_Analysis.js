// load Trace Compass modules
loadModule('/TraceCompass/Analysis');
loadModule('/TraceCompass/DataProvider');
loadModule('/TraceCompass/Trace');
loadModule('/TraceCompass/View');

// Get the active trace
var trace = getActiveTrace();

// Create an analysis named activetid.js
var analysis = createScriptedAnalysis(trace, "activetid.js");

if (analysis == null) {
	print("Trace is null");
	exit();
}

// Get the analysis's state system so we can fill it, false indicates to create a new state system even if one already exists, true would re-use an existing state system
var ss = analysis.getStateSystem(false);

// The analysis itself is in this function
function runAnalysis() {
	// Get the event iterator for the trace
	var iter = analysis.getEventIterator();

	var event = null;
	// Parse all events
    var processes_dict = {}


	while (iter.hasNext()) {
		//print(iter.length)
		event = iter.next();


		event_name = event.getName()
		timestamp = event.getTimestamp()


		prev_command = getEventFieldValue(event, "prev_comm");
		next_command = getEventFieldValue(event, "next_comm");
		procname = getEventFieldValue(event, "context._procname");
		pid = getEventFieldValue(event, "context._vpid");
		dport = getEventFieldValue(event, "dport");


		//content = getEventFieldValue(event, "context._procname");
		skb_address = getEventFieldValue(event, "skbaddr");
		skb_addr = null;

		if (skb_address != null){
			skb_addr = skb_address.longValue()
		}

		src_addr = null;
		dest_addr = null;
		protocol = null;
		seq_number = null;
		ack_seq_number = null;

		udp_dest_port = null;
		udp_source_port = null;
        tcp_source_port = null;
        tcp_dest_port = null;

		tcp_flags = null;

		netwrok_header = getEventFieldValue(event, "network_header")
		transport_header = null;

		if (netwrok_header != null){
			try {
				src_addr = netwrok_header.getField('saddr').getFormattedValue().toString()
				dest_addr = netwrok_header.getField('daddr').getFormattedValue().toString()
				protocol = netwrok_header.getField('protocol').getFormattedValue().toString()
				length = netwrok_header.getField('tot_len').getFormattedValue().toString()
			}
			catch (error) {}

			transport_header = netwrok_header.getField('transport_header')
			if (transport_header != null){
				udp = transport_header.getField('udp')
				tcp = transport_header.getField('tcp')
				if (udp != null){
					udp_source_port = udp.getField('source_port').getFormattedValue().toString()
					udp_dest_port = udp.getField('dest_port').getFormattedValue().toString()


				}

				if (tcp != null){
					seq_number = tcp.getField('seq').getFormattedValue()
					ack_seq_number = tcp.getField('ack_seq').getFormattedValue()

					tcp_flags = tcp.getField('flags').getFormattedValue().toString()
					tcp_source_port = tcp.getField('source_port').getFormattedValue().toString()
					tcp_dest_port = tcp.getField('dest_port').getFormattedValue().toString()
					//print(tcp_flags)
				}
			}

            if (event_name == "net_dev_queue" || event_name == "net_if_receive_skb"){
                source_port = tcp_source_port
                if (source_port == null)
                    source_port = udp_source_port

                previous_state = null
				dns_resolved = false

                if (pid+source_port in processes_dict){
                    previous_state = processes_dict[pid+source_port]["state"]
					dns_resolved = processes_dict[pid+source_port]["DNS_RESOLVED"]
				}

                processes_dict[pid+source_port] = {"process_name":procname, "pid":pid, "protocol":protocol, "source_address":src_addr,
                "dest_address":dest_addr, "tcp_source_port": tcp_source_port, "tcp_dest_port":tcp_dest_port,
                "udp_source_port": udp_source_port, "udp_dest_port":udp_dest_port, "state":previous_state, "DNS_RESOLVED":dns_resolved,
				"seq":seq_number, "ack_seq":ack_seq_number}

                if (protocol == '_udp' && (udp_source_port == '53' || udp_dest_port =='53') && !processes_dict[pid+source_port]['DNS_RESOLVED']){

					processes_dict[pid+source_port]["state"] = "DNS"
					if ("number_of_dns_requests" in processes_dict[pid+source_port])
						processes_dict[pid+source_port]["number_of_dns_requests"] += 1
					else
						processes_dict[pid+source_port]["number_of_dns_requests"] = 1

					for (pid2 in processes_dict){
						if (processes_dict[pid2]["state"] == "DNS" &&
							udp_source_port == processes_dict[pid2]["udp_dest_port"] &&
                        	udp_dest_port == processes_dict[pid2]["udp_source_port"] &&
							processes_dict[pid+source_port]["number_of_dns_requests"] == processes_dict[pid2]["number_of_dns_requests"]
							)
						{
							processes_dict[pid2]["state"] = null
							processes_dict[pid+source_port]["state"] = null
							processes_dict[pid2]["DNS_RESOLVED"] = true
							processes_dict[pid+source_port]["DNS_RESOLVED"] = true
						}

					}
				}

                else if (protocol == '_tcp' && tcp_flags == '0x2'){
                    processes_dict[pid+source_port]["state"] = "SYN (Waiting for SYN-ACK)"

                }


                else if (protocol == '_tcp' && tcp_flags == '0x12'){
					processes_dict[pid+source_port]["state"] = "SYN-ACK"
                    for (var pid2 in processes_dict){
                        if (processes_dict[pid2]["state"] == "SYN (Waiting for SYN-ACK)" &&
                        tcp_source_port == processes_dict[pid2]["tcp_dest_port"] &&
                        tcp_dest_port == processes_dict[pid2]["tcp_source_port"]){
                            processes_dict[pid2]["state"] = null
                        }
                    }
                }

                else if (protocol == '_tcp' && tcp_flags == '0x10'){

                    for (var pid2 in processes_dict){
						pid2_last_state = processes_dict[pid2]["state"]
						
						if (seq_number == processes_dict[pid2]["ack_seq"])
                            processes_dict[pid2]["state"] = null

						if (seq_number == processes_dict[pid2]["ack_seq"] && pid2_last_state == "FIN_ACK")
							processes_dict[pid+source_port]["state"] = "LAST ACK (CONNECTION OVER)"
										
						else if (processes_dict[pid+source_port]["state"] != "LAST ACK (CONNECTION OVER)")
							processes_dict[pid+source_port]["state"] = "ACK"

                    }

                }
				else if (protocol == '_tcp' && tcp_flags == '0x18'){

					for (var pid2 in processes_dict){
						if (seq_number == processes_dict[pid2]["seq"]){
							processes_dict[pid2]["state"] = null
                        }
                    }
					processes_dict[pid+source_port]["state"] = "DATA"

				}

				if (protocol == '_tcp' && tcp_flags == '0x11'){
                    for (var pid2 in processes_dict){
                        if (processes_dict[pid2]["state"] == "DATA" &&
                        tcp_source_port == processes_dict[pid2]["tcp_dest_port"] &&
                        tcp_dest_port == processes_dict[pid2]["tcp_source_port"]){
                            processes_dict[pid2]["state"] = null
                        }
                    }

					for (var pid2 in processes_dict){
						if (
							(tcp_source_port == processes_dict[pid2]["tcp_dest_port"] && tcp_dest_port == processes_dict[pid2]["tcp_source_port"]) ||
						(tcp_source_port == processes_dict[pid2]["tcp_source_port"] && tcp_dest_port == processes_dict[pid2]["tcp_dest_port"])
						)
						processes_dict[pid2]["state"] = null

					}
					processes_dict[pid+source_port]["state"] = "FIN_ACK"
                }

            }
		}


        for (var pid in processes_dict){
            if (processes_dict[pid]["protocol"] == '_tcp'){
                y_axis_name = processes_dict[pid]["process_name"] + '_'+ processes_dict[pid]["pid"]+" "+ processes_dict[pid]["source_address"].replace(', ', '.') +":"+processes_dict[pid]["tcp_source_port"] + "->" +  processes_dict[pid]["dest_address"].replace(', ', '.')+":"+processes_dict[pid]["tcp_dest_port"]
			}
			else if (processes_dict[pid]["protocol"] == '_udp')
			y_axis_name = processes_dict[pid]["process_name"] + '_'+ processes_dict[pid]["pid"]+" "+ processes_dict[pid]["source_address"].replace(', ', '.') +":"+processes_dict[pid]["udp_source_port"] + "->" +  processes_dict[pid]["dest_address"].replace(', ', '.')+":"+processes_dict[pid]["udp_dest_port"]

			if (processes_dict[pid]["state"] == "DATA")
				processes_dict[pid]["state"] = "DATA "+"(Length:"+length+")"

            stage = ss.getQuarkAbsoluteAndAdd(y_axis_name);
            ss.modifyAttribute(event.getTimestamp().toNanos(), processes_dict[pid]['state'], stage);
        }

	}


	// Done parsing the events, close the state system at the time of the last event, it needs to be done manually otherwise the state system will still be waiting for values and will not be considered finished building
	if (event != null) {
		ss.closeHistory(event.getTimestamp().toNanos());
	}
}

// This condition verifies if the state system is completed. For instance, if it had been built in a previous run of the script, it wouldn't run again.
if (!ss.waitUntilBuilt(0)) {
	// State system not built, run the analysis
	runAnalysis();
}


function getEntries(filter) {
	quarks = ss.getQuarks("*");
	// Prepare the CPU names and sort them
	var cpus = [];
	for (i = 0; i < quarks.size(); i++) {
		quark = quarks.get(i);
		cpus.push(ss.getAttributeName(quark));
	}
	cpus.sort(function(a,b){return Number(a) - Number(b)});
	var entries = [];
	for (i = 0; i < cpus.length; i++) {
		cpu = cpus[i];
		quark = ss.getQuarkAbsolute(cpu);
		entries.push(createEntry({'quark' : quark, 'name' : "CPU " + cpu}));
	}
	return entries;
}




provider = createTimeGraphProvider(analysis, {'path' : '*'});
if (provider != null) {
	// Open a time graph view displaying this provider
	openTimeGraphView(provider);
}

print("Done");
