#!/usr/bin/ruby
require 'mysql'

class IP_Stat_Calculator     
    attr_accessor :total_flows, :without_ACK_cnt, :under_3_packets_cnt, 
	   :over_60_Bpp_cnt, :standard_pattern_cnt, :standard_flags_cnt,
	   :backscatter_flags_cnt, :backscatter_pattern_cnt, :src_port_hash,
	   :subnet_hash, :dst_IP_hash, :avg_src_ports_per_dst_IP,
	   :max_low_ports, :max_high_ports, :max_consec_high, :max_consec_low,
	   :median_packets_per_dst_IP

    def initialize 
	   @total_flows = 0

	   @without_ACK_cnt = 0
	   @under_3_packets_cnt = 0
	   @over_60_Bpp_cnt = 0

	   @standard_flags_cnt = 0
	   @standard_pattern_cnt = 0

	   @backscatter_flags_cnt = 0
	   @backscatter_pattern_cnt = 0

	   @src_port_hash = Hash.new()
	   @subnet_hash = Hash.new()
	   @dst_IP_hash = Hash.new()

	   @avg_src_ports_per_dst_IP = 0

	   @max_low_ports = 0
	   @max_high_ports = 0
	   @max_consec_high = 0
	   @max_consec_low = 0

	   @median_packets_per_dst_IP = 0
    end

    def subnet_identify(dst_IP)
	   if !(@dst_IP_hash.has_key?(dst_IP))
		  if @subnet_hash.has_key?(dst_IP.to_i >> 4)
			 @subnet_hash[dst_IP.to_i >> 4] += 1
		  else
			 @subnet_hash[dst_IP.to_i >> 4] = 1
		  end
	   end
    end

    def calculate_initial_dst_IP_stats(flow)
	   dst_IP = flow[5]
	   dst_port = flow[6].to_f
	   src_port = flow[4]
	   packets = flow[9].to_f

	   #if dst_IP is new, create new entry to hold its data
	   if !(@dst_IP_hash.has_key?(dst_IP))
		  @dst_IP_hash[dst_IP] = Hash.new()
		  @dst_IP_hash[dst_IP]["packets"] = 0
		  @dst_IP_hash[dst_IP]["high_dst_ports"] = Hash.new()
		  @dst_IP_hash[dst_IP]["low_dst_ports"] = Hash.new()
		  @dst_IP_hash[dst_IP]["src_ports"] = Hash.new()
	   end
	   @dst_IP_hash[dst_IP]["packets"] += packets
	   @dst_IP_hash[dst_IP]["src_ports"][src_port] = 1
	   if dst_port > 1024
		  @dst_IP_hash[dst_IP]["high_dst_ports"][dst_port] = 1
	   else
		  @dst_IP_hash[dst_IP]["low_dst_ports"][dst_port] = 1
	   end
    end

    def calculate_end_dst_IP_stats()
	   median = 0
	   pac_len = 0
	   packets_per_IP = Array.new()
	   src_ports_per_IP = Array.new()
	   low_ports_per_IP = Array.new()
	   high_ports_per_IP = Array.new()
	   total = 0

	   #first, loop to do some array filling
	   @dst_IP_hash.each_key do |ip|
		  packets_per_IP.push(@dst_IP_hash[ip]["packets"])
		  src_ports_per_IP.push(@dst_IP_hash[ip]["src_ports"].length)
		  high_ports_per_IP.push(@dst_IP_hash[ip]["high_dst_ports"].length)
		  low_ports_per_IP.push(@dst_IP_hash[ip]["low_dst_ports"].length)
	   end


	   #median_packets_per_dst_IP
	   packets_per_IP.sort!
	   pac_len = packets_per_IP.length
	   if pac_len.even?
		  median = ((packets_per_IP[pac_len / 2] + packets_per_IP[(pac_len / 2) - 1]) / 2)
	   else
		  median = packets_per_IP[pac_len / 2]
	   end
	   @median_packets_per_dst_IP = median

	   #next, avg_src_ports_per_dst_IP
	   src_ports_per_IP.each do |num|
		  total += num
	   end
	   @avg_src_ports_per_dst_IP = total.to_f / src_ports_per_IP.length.to_f


	   #max high and low num of ports per IP
	   high_ports_per_IP.sort!
	   low_ports_per_IP.sort!
	   @max_high_ports = high_ports_per_IP.last
	   @max_low_ports = low_ports_per_IP.last


	   #max consec high and low ports per IP
	   @dst_IP_hash.each_key do |ip|
		  curr_max = 1
		  curr_count = 1
		  ports = @dst_IP_hash[ip]["high_dst_ports"].keys
		  ports.sort!
		  second = 1
		  first = 0
		  (ports.size - 1).times do
			 if (ports[second]  == (ports[first] + 1))
				curr_count += 1
				if (curr_count > curr_max)
				    curr_max = curr_count
				    puts curr_count
				end
			 else 
				curr_count = 1
			 end
			 second += 1
			 first += 1
		  end
		  if curr_max > @max_consec_high
			 @max_consec_high = curr_max
		  end
		  curr_max = 1
		  curr_count = 1

		  ports = @dst_IP_hash[ip]["low_dst_ports"].keys
		  ports.sort!
		  second = 1
		  first = 0
		  (ports.size - 1).times do
			 if (ports[second]  == (ports[first] + 1))
				curr_count += 1
				if (curr_count > curr_max)
				    curr_max = curr_count
				end
			 else 
				curr_count = 1
			 end
			 second += 1
			 first += 1
		  end
		  if curr_max > @max_consec_low
			 @max_consec_low = curr_max
		  end
	   end
    end

    def has_backscatter_flags(flags)
	   if ((flags.include? "R") || ((flags.include? "S") && (flags.include? "A")))
		  @backscatter_flags_cnt += 1
	   end
    end

    def has_backscatter_pattern(flags, bpp, packets)
	   if (bpp <= 60 && packets < 3 && (flags.include? "R" || ((flags.include? "S") && (flags.include? "A")))) 
		  @backscatter_pattern_cnt += 1
	   end
    end

    def has_standard_flags(flags)
	   if  ((flags.include? "A") && (flags.include? "S") && ((flags.include? "F") || (flags.include? "R")))
		  @standard_flags_cnt += 1
	   end
    end

    def has_standard_pattern(flags, bpp, packets)
	   if (packets >= 3 && bpp > 60 && ((flags.include? "A") && (flags.include? "S") && ((flags.include? "F") || (flags.include? "R"))))
		  @standard_pattern_cnt += 1
	   end
    end 

    def has_under_3_packets(packets)
	   if packets < 3
		  @under_3_packets_cnt += 1
	   end
    end

    def has_over_60_Bpp(bpp)
	   if bpp > 60
		  @over_60_Bpp_cnt += 1
	   end
    end

    def has_no_ACK_flag(flags)
	   if !(flags.include? "A")
		  @without_ACK_cnt += 1
	   end
    end
end

begin
    con = Mysql.new 'localhost', 'root', 'cyberaces', 'netflow_db' #open connection
    all_src_ips = con.query("SELECT DISTINCT src_IP FROM netflow_full") #get all the distinct src IPS

    #for each src IP, caclulate it's statistics by grabbing all its flows and processing them
    all_src_ips.each do |ip|
	   c = IP_Stat_Calculator.new
	   ip_data = con.query("SELECT * FROM netflow_full WHERE src_IP = '#{ip[0]}'")
	   ip_data.each do |flow|
		  #total flows count
		  c.total_flows += 1

		  #for calculation 1 
		  c.has_no_ACK_flag(flow[7])

		  #for calculations 2,11,12,14
		  c.has_standard_flags(flow[7])
		  c.has_under_3_packets(flow[9].to_i)
		  c.has_over_60_Bpp(flow[13].to_i)
		  c.has_standard_pattern(flow[7], flow[13].to_i, flow[9].to_i)

		  #for calculations 15,18
		  c.has_backscatter_flags(flow[7])
		  c.has_backscatter_pattern(flow[7], flow[13].to_i, flow[9].to_i)

		  #for calculations 9, 17
		  c.src_port_hash[flow[4]] = 1

		  #for calculation 3
		  c.subnet_identify(flow[5])

		  #for calculation 4-8,10,13,16
		  c.calculate_initial_dst_IP_stats(flow)
	   end

	   c.calculate_end_dst_IP_stats()
	   puts ("IP: #{ip[0]}")
	   puts ("W/o_ACK_Ratio: #{c.without_ACK_cnt.to_f/c.total_flows.to_f} Under_3_packets_ratio: #{c.under_3_packets_cnt.to_f/c.total_flows.to_f}") #1,2
	   puts ("Most_IPs_in_one_subnet: #{c.subnet_hash.values.sort.last}") #3
	   puts ("Max_high_ports: #{c.max_high_ports} Max_low_ports: #{c.max_low_ports}") #4,5
	   puts ("Max_consec_high: #{c.max_consec_high} Max_consec_low: #{c.max_consec_low}") #6,7
	   puts ("Num_dst_IPs: #{c.dst_IP_hash.length} Num_src_ports: #{c.src_port_hash.length}") #8,9
	   puts ("Avg_src_ports_per_dst_IP: #{c.avg_src_ports_per_dst_IP}") #10
	   puts ("Std_flags_ratio: #{c.standard_flags_cnt.to_f/c.total_flows.to_f} Over_60_ratio: #{c.over_60_Bpp_cnt.to_f/c.total_flows.to_f}") #11,12
	   puts ("Median_packets_per_dst_IP: #{c.median_packets_per_dst_IP}") #13
	   puts ("Std_pat_ratio: #{c.standard_pattern_cnt.to_f/c.total_flows.to_f}") #14
	   puts ("Bcsctr_pat_ratio: #{c.backscatter_pattern_cnt.to_f/c.total_flows.to_f}") #15
	   puts ("Num_dst_Ips_to_flows: #{c.dst_IP_hash.length.to_f/c.total_flows.to_f}") #16
	   puts ("Num_src_ports_to_flows: #{c.src_port_hash.length.to_f/c.total_flows.to_f}") #17
	   puts ("Bcsctr_flags_ratio: #{c.backscatter_flags_cnt.to_f/c.total_flows.to_f}") #18
    end

rescue Mysql::Error => e
    puts e.errno
    puts e.error

ensure
    con.close if con
end
