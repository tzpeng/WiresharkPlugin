-- Dump RTP AAC payload to raw file
-- Write it to from<sourceIp_sourcePort>to<dstIp_dstPort> file.
-- You can access this feature by menu "Tools"
-- Author: Yang Xing (hongch_911@126.com)
------------------------------------------------------------------------------------------------
do
    -- 解析为AAC音频部分
    local proto_aac = Proto("aac", "Audio AAC")

    -- Wireshark对每个相关数据包调用该函数
    -- tvb:Testy Virtual Buffer报文缓存; pinfo:packet infomarmation报文信息; treeitem:解析树节点
    function proto_aac.dissector(tvb, pinfo, tree)
        -- add proto item to tree
        local proto_tree = tree:add(proto_aac, tvb())
        proto_tree:append_text(string.format(" (Len: %d)",tvb:len()))
        pinfo.columns.protocol = "AAC"
    end

    -- set this protocal preferences
    local prefs = proto_aac.prefs
    prefs.dyn_pt = Pref.range("AAC dynamic payload type", "", "Dynamic payload types which will be interpreted as AAC; Values must be in the range 96 - 127", 127)

    -- register this dissector to dynamic payload type dissectorTable
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")
    dyn_payload_type_table:add("aac", proto_aac)

    -- register this dissector to specific payload type (specified in preferences windows)
    local payload_type_table = DissectorTable.get("rtp.pt")
    local old_dyn_pt = nil
    local old_dissector = nil

    function proto_aac.init()
        if (prefs.dyn_pt ~= old_dyn_pt) then
            -- reset old dissector
            if (old_dyn_pt ~= nil and string.len(old_dyn_pt) > 0) then
                local pt_numbers = getArray(tostring(old_dyn_pt))
                for index,pt_number in pairs(pt_numbers) do
                    -- replace this proto with old proto on old payload type
                    if old_dissector ~= nil and old_dissector[index] ~= nil then
                        payload_type_table:add(pt_number, old_dissector[index])
                    else -- just remove this proto
                        payload_type_table:remove(pt_number, proto_aac)
                    end
                end
            end

            old_dyn_pt = prefs.dyn_pt  -- save current payload type's dissector

            if (prefs.dyn_pt ~= nil and string.len(prefs.dyn_pt) > 0) then
                local pt_numbers = getArray(tostring(prefs.dyn_pt))
                old_dissector = {}
                for index,pt_number in pairs(pt_numbers) do
                    local dissector = payload_type_table:get_dissector(pt_number)
                    -- table.insert(old_dissector,index,dissector)
                    old_dissector[index] = dissector
                    payload_type_table:add(pt_number, proto_aac)
                end
            end
        end
    end

    function getArray(str)
        local strList = {}
        string.gsub(str, '[^,]+',function (w)
            local pos = string.find(w,'-')
            if not pos then
                table.insert(strList,tonumber(w))
            else
                local begin_index = string.sub(w,1,pos-1)
                local end_index = string.sub(w,pos+1,#w)
                for index = begin_index,end_index do
                    table.insert(strList,index)
                end
            end
        end)
        return strList
    end

    function get_temp_path()
        local tmp = nil
        if tmp == nil or tmp == '' then
            tmp = os.getenv('HOME')
            if tmp == nil or tmp == '' then
                tmp = os.getenv('USERPROFILE')
                if tmp == nil or tmp == '' then
                    tmp = persconffile_path('temp')
                else
                    tmp = tmp .. "/wireshark_temp"
                end
            else
                tmp = tmp .. "/wireshark_temp"
            end
        end
        return tmp
    end

    -- 导出数据到文件部分
    -- for geting data (the field's value is type of ByteArray)
    local f_data = Field.new("aac")

    local filter_string = nil

    -- *** 1. 新增开关 ***
    local add_adts_header = true          -- true=加ADTS头，false=保持原格式

    -- menu action. When you click "Tools" will run this function
    local function export_data_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export File Info Win")

        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end

        -- temp path
        local temp_path = get_temp_path()

        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil

        -- trigered by all ps packats
        local list_filter = ''
        if filter_string == nil or filter_string == '' then
            list_filter = "aac"
        elseif string.find(filter_string,"aac")~=nil then
            list_filter = filter_string
        else
            list_filter = "aac && "..filter_string
        end
        twappend("Listener filter: " .. list_filter .. "\n")
        local my_tap = Listener.new("frame", list_filter)

        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port) .. "_to_" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
            key = key:gsub(":", ".")
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                stream_info = { }
                stream_info.filename = key.. ".aac"
                -- stream_info.file = io.open(stream_info.filename, "wb")
                if not Dir.exists(temp_path) then
                    Dir.make(temp_path)
                end
                stream_info.filepath = temp_path.."/"..stream_info.filename
                stream_info.file,msg = io.open(temp_path.."/"..stream_info.filename, "wb")
                if msg then
                    twappend("io.open "..stream_info.filepath..", error "..msg)
                end
                stream_infos[key] = stream_info
                twappend("Ready to export data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " write to file:[" .. stream_info.filename .. "] ...\n")
            end
            return stream_info
        end



        --------------------------------------------------------------------------------------------
        -- ADTS 头生成（7 字节，无 CRC）
        --------------------------------------------------------------------------------------------
		local samplerate_map = {
			[96000] = 0, [88200] = 1, [64000] = 2, [48000] = 3,
			[44100] = 4, [32000] = 5, [24000] = 6, [22050] = 7,
			[16000] = 8, [12000] = 9, [11025] = 10, [8000] = 11,
		}

		-- 快速 2^n 表
		local pow2 = {}
		for i = 0, 13 do
			pow2[i] = 2^i
		end

		-- 把 v 写进 bits 表，高位在前，共 len 位
		local function write(bits, v, len)
			for i = len - 1, 0, -1 do
				-- 使用位与操作替代浮点运算，提高精度和性能
				bits[#bits + 1] = (bit32 and bit32.extract(v, i) or (math.floor(v / pow2[i]) % 2))
			end
		end

		-- 主函数
		-- profile:  0=Main, 1=LC, 2=SSR, 3=LTP
		-- samplerate: 例如 16000
		-- channels: 1=mono, 2=stereo ...
		-- frame_length: 原始 AAC 裸帧长度（不含 ADTS 头）
		local function make_adts_header(profile, samplerate, channels, frame_length)
			-- 参数检查
			local sr_idx = samplerate_map[samplerate]
			if not sr_idx then
				return nil, "unsupported samplerate: " .. tostring(samplerate)
			end
			if not (profile >= 0 and profile <= 3) then
				return nil, "bad profile: " .. tostring(profile)
			end
			if not (channels >= 1 and channels <= 7) then
				return nil, "bad channels: " .. tostring(channels)
			end

			local full_frame = frame_length + 7
			if full_frame >= 8192 then
				return nil, "frame too big: " .. tostring(full_frame)
			end

			-- /* adts_fixed_header */
			-- put_bits(&pb, 12, 0xfff);	/* syncword */
			-- put_bits(&pb, 1, 0); /* ID */
			-- put_bits(&pb, 2, 0);	/* layer */
			-- put_bits(&pb, 1, 1);	/* protection_absent */
			-- put_bits(&pb, 2, objecttype); /* profile_objecttype */
			-- put_bits(&pb, 4, freqindex);
			-- put_bits(&pb, 1, 0);	/* private_bit */
			-- put_bits(&pb, 3, channels); /* channel_configuration */
			-- put_bits(&pb, 1, 0);	/* original_copy */
			-- put_bits(&pb, 1, 0);	/* home */

			-- /* adts_variable_header */
			-- put_bits(&pb, 1, 0);	/* copyright_identification_bit */
			-- put_bits(&pb, 1, 0);	/* copyright_identification_start */
			-- put_bits(&pb, 13, 7 + pkt_size); /* aac_frame_length */
			-- put_bits(&pb, 11, 0x7ff);	/* adts_buffer_fullness */
			-- put_bits(&pb, 2, 0);	/* number_of_raw_data_blocks_in_frame */

			-- 拼 56 位
			local bits = {}
			write(bits, 0xFFF, 12)      -- syncword
			write(bits, 0,      1)      -- MPEG-4
			write(bits, 0,      2)      -- layer 0
			write(bits, 1,      1)      -- no CRC
			write(bits, profile,2)      -- profile
			write(bits, sr_idx, 4)      -- sampling frequency index
			write(bits, 0,      1)      -- private bit
			write(bits, channels,3)     -- channel configuration
			write(bits, 0,      1)      -- original/copy
			write(bits, 0,      1)      -- home
			write(bits, 0,      1)      -- copyright_identification_bit
			write(bits, 0,      1)      -- copyright_identification_start
			write(bits, full_frame, 13) -- frame length
			write(bits, 0x7FF,  11)     -- buffer fullness
			write(bits, 0,      2)      -- number of raw data blocks

			-- 7 字节打包
			local bytes = {}
			for byte_i = 0, 6 do
				local v = 0
				for bit_i = 0, 7 do
					v = v * 2 + (bits[byte_i * 8 + bit_i + 1] or 0)
				end
				bytes[byte_i + 1] = v
			end

			twappend(string.format("ADTS header: %02X %02X %02X %02X %02X %02X %02X",
								bytes[1], bytes[2], bytes[3], bytes[4],
								bytes[5], bytes[6], bytes[7]))

			return string.char(unpack(bytes))
		end

        -- write data to file.
        local function write_to_file(stream_info, data_bytes)
            local raw      = data_bytes:raw()
            local dataOffset = 4 + 1               -- au 占 4 字节 Lua下标从 1 开始
            twappend("###### dataOffset #######" .. tostring(dataOffset))
            twappend("###### data_bytes:len #######" .. tostring(data_bytes:len()))
            -- *** 3. 若开关打开，先写ADTS头 ***
            if add_adts_header then
                stream_info.file:write(make_adts_header(1, 16000, 1, data_bytes:len() - 4))
            end
            -- local b1=string.char(len%256) len=(len-len%256)/256
            -- local b2=string.char(len%256) len=(len-len%256)/256
            -- stream_info.file:write(b1,b2)
            stream_info.file:write(raw:sub(dataOffset))
        end

        -- call this function if a packet contains ps payload
        function my_tap.packet(pinfo,tvb)
            if stream_infos == nil then
                -- not triggered by button event, so do nothing.
                return
            end
            local datas = { f_data() } -- using table because one packet may contains more than one RTP

            for i,data_f in ipairs(datas) do
                if data_f.len < 1 then
                    return
                end
                local data = data_f.range:bytes()
                local stream_info = get_stream_info(pinfo)
                write_to_file(stream_info, data)
            end
        end

        -- close all open files
        local function close_all_files()
            if stream_infos then
                local no_streams = true
                for id,stream in pairs(stream_infos) do
                    if stream and stream.file then
                        stream.file:flush()
                        stream.file:close()
                        stream.file = nil
                        twappend("File [" .. stream.filename .. "] generated OK!")
                        no_streams = false
                    end
                end

                if no_streams then
                    twappend("Not found any Data over RTP streams!")
                else
                    tw:add_button("Browser", function () browser_open_data_file(temp_path) end)
                end
            end
        end

        function my_tap.reset()
            -- do nothing now
        end

        tw:set_atclose(function ()
            my_tap:remove()
            if Dir.exists(temp_path) then
                Dir.remove_all(temp_path)
            end
        end)

        local function export_data()
            stream_infos = {}
            retap_packets()
            close_all_files()
            stream_infos = nil
        end

        tw:add_button("Export All", function ()
            export_data()
        end)

        tw:add_button("Set Filter", function ()
            tw:close()
            dialog_menu()
        end)
    end

    local function dialog_func(str)
        filter_string = str
        export_data_to_file()
    end

    function dialog_menu()
        new_dialog("Filter Dialog",dialog_func,"Filter")
    end

    local function dialog_default()
        filter_string = get_filter()
        export_data_to_file()
    end

    -- Find this feature in menu "Tools"
    register_menu("Audio/Export AAC", dialog_default, MENU_TOOLS_UNSORTED)
end
