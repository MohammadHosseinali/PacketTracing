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
	var arr = []
	var skb_array = []

	var target_process = argv[0]
	if (target_process == null){
		print("Please enter a process name as argument in configuration menu!");
		return;
	}
	print(argv[0])

	var target_ip = null;
    var dns_port = null;

	var dns_requests_sent = 0;
	var dns_requests_received = 0;


	var handshake_done = false;
	var data_transmission_done = false;

	var current_stage = String()

	while (iter.hasNext()) {
		//print(iter.length)
		event = iter.next();
		
		prev_command = getEventFieldValue(event, "prev_comm");
		next_command = getEventFieldValue(event, "next_comm");
		procname = getEventFieldValue(event, "context._procname");
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
		
		dns_dest_port = null;
		dns_src_port = null;

		tcp_flags = null;

		netwrok_header = getEventFieldValue(event, "network_header")
		transport_header = null;
		
		if (netwrok_header != null){
			try {
				src_addr = netwrok_header.getField('saddr').getFormattedValue().toString()
				dest_addr = netwrok_header.getField('daddr').getFormattedValue().toString()
				protocol = netwrok_header.getField('protocol').getFormattedValue().toString()	
			} 
			catch (error) {}

			transport_header = netwrok_header.getField('transport_header')
			if (transport_header != null){
				udp = transport_header.getField('udp')
				tcp = transport_header.getField('tcp')
				if (udp != null){
					dns_src_port = udp.getField('source_port').getFormattedValue().toString()
					dns_dest_port = udp.getField('dest_port').getFormattedValue().toString()
					
					if(procname == target_process && dns_port == null){
						dns_port = dns_src_port;
					}

					if (dns_src_port == dns_port)
						dns_requests_sent += 1
					if (dns_dest_port == dns_port)
						dns_requests_received += 1		
				}
				
				if (tcp != null){
					tcp_flags = tcp.getField('flags').getFormattedValue().toString()
					//print(tcp_flags)
				}
			}
			
		}

		
		event_name = event.getName()
		timestamp = event.getTimestamp()


		if(procname==target_process || prev_command == target_process || next_command == target_process || target_ip!=null && (src_addr == target_ip || dest_addr == target_ip) || skb_array.indexOf(skb_addr) >= 0 || (dns_port != null && dns_dest_port == dns_port)){
			if (target_ip == null && protocol == "_tcp"){
				target_ip = dest_addr;
			}

			if (skb_addr != null){
				skb_array.push(skb_addr)
			}
							

			var data = []
			data.push(event_name)
			data.push(timestamp)
			data.push(next_command)
			arr.push(data)

			stage = ss.getQuarkAbsoluteAndAdd(0);
			
			if (dport == 53) 
				current_stage = "DNS"

			else if (current_stage == "DNS" && dns_requests_sent > 0 && dns_requests_sent == dns_requests_received)
				current_stage = ""
			
			else if (tcp_flags == '0x2'){ //SYN
				current_stage = "Handshake"
			}
			else if (current_stage == "Handshake" && tcp_flags == '0x10'){ //ACK
				current_stage = ""
				handshake_done = true;
			}


			else if (handshake_done && event_name == 'syscall_entry_sendto'){
				current_stage = "Data Transmission";
			}
			
			else if (current_stage == "Data Transmission" && tcp_flags == '0x11'){
				current_stage = ""
				data_transmission_done = true;
			}

			else if (data_transmission_done && tcp_flags == '0x10'){
				current_stage = "Connection Close"
			}
			
			else if (current_stage == "Connection Close" && event_name == 'skb_kfree'){
				current_stage = ""
			}

			ss.modifyAttribute(event.getTimestamp().toNanos(), current_stage, stage);
			

		}

	}

	for (let i = 0; i < arr.length; i++){
		print(arr[i][0] + " " + arr[i][1]);
	}

	print(arr.length)
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
