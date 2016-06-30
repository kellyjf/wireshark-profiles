-- skew.lua
-- A post-dissector to compute the difference between system and RTP time
-- for RTP streams separately by SSRC
--
-- Author: John Kelly
-- Date:   2/26/2014
--

-- Helper function for debugging
function print_table(x)
	for k,v in pairs(x) do
		print(k,v)
	end
end

do
	-- Create the 'new protocol' dissector
        local rtp_wrapper_proto = Proto("rtp_extra", "RTP Skew Analysis");

	-- Create the new fields, and associate to the protocol
        local F_skew = ProtoField.double("rtp.skew", "Skew")
        local F_skew_abs = ProtoField.double("rtp.skew_abs", "Abs Skew")
        local F_skew_bad = ProtoField.bool("rtp.skew_bad", "Off track skew")
        rtp_wrapper_proto.fields = {F_skew,F_skew_abs, F_skew_bad}

	-- Create acccessors for the fields we need to reference
        local f_ssrc = Field.new("rtp.ssrc")
        local f_rtp_time = Field.new("rtp.timestamp")
        local f_frame_time    = Field.new("frame.time_epoch")

	-- Create an empty table to store initial offsets by SSRC
	local start_offset = {} 

	-- Define the dissector function
        function rtp_wrapper_proto.dissector(tvbuffer, pinfo, treeitem)

		-- Only attach to packet parsed as RTP (use timestamp != nil)
		if(f_rtp_time()) then

			-- Store the top of the analysis tree
			local subtreeitem = treeitem:add(rtp_wrapper_proto, tvbuffer)

			-- Compute skew and SSRC
			skew_val=tostring(f_frame_time())-tostring(f_rtp_time())/8000.0
			ssrc_val=tostring(f_ssrc())

			-- Save off as initial value
			if( not (start_offset[ssrc_val])) then
				start_offset[ssrc_val] = skew_val
			end

			--print(ssrc_val,f_frame_time(),f_rtp_time(),skew_val,start_offset[ssrc_val],(skew_val - start_offset[ssrc_val]))

			-- Calibrate skew to initial skew
			skew_val = skew_val - start_offset[ssrc_val]

			-- Add the values to the analysis tree
			subtreeitem:add(F_skew, tvbuffer(), 1000*skew_val)
				   :set_text("Skew: " ..tostring(1000*skew_val))
			subtreeitem:add(F_skew_abs, tvbuffer(), math.abs(1000*skew_val))
				   :set_text("Abs Skew: " ..tostring(math.abs(1000*skew_val)))

			-- Check if we've gone off the rails
			if( (math.abs(skew_val)) > 2000.0) then

				-- Reset offset and mark the packet
				start_offset[ssrc_val] = start_offset[ssrc_val]+skew_val
				subtreeitem:add(F_skew_bad, tvbuffer(), 1)
					   :set_text("Bad Skew")
			end
		end
        end
	register_postdissector(rtp_wrapper_proto)
end
