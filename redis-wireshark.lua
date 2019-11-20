-- Wireshark packet dissector for Redis
-- Protocol specification: http://redis.io/topics/protocol
-- Written by John Zwinck, 29 November 2011

do -- scope
    local proto = Proto('redis', 'Redis')

    local f = proto.fields
    -- we could make more of these, e.g. to distinguish keys from values
    f.bulk_reply_num   = ProtoField.string('redis.bulk_reply_num',   'bulk_reply_num')
    f.value   = ProtoField.string('redis.value',   'Value')
    f.size   = ProtoField.string('redis.value_size',   'Value Size')

    function proto.dissector(buffer, pinfo, tree)
        pinfo.cols.protocol = 'Redis'

        mtypes = {
            ['+'] = 'Status',
            ['-'] = 'Error',
            [':'] = 'Integer',
            ['$'] = 'Bulk',
            ['*'] = 'Multi-Bulk',
        }

        local CRLF = 2 -- constant length of \r\n

        local function matches(buffer, match_offset)
            return buffer(match_offset):string():match('[^\r\n]+')
        end
        -- recursively parse and generate a tree of data from messages in a packet
        -- parent: the tree root to populate under
        -- buffer: the entire packet buffer
        -- offset: the current offset in the buffer
        -- returns: the new offset (i.e. the input offset plus the number of bytes consumed)
        local function recurse(parent, buffer, offset)
            local line = matches(buffer, offset) -- get next line
            local length = line:len()

            local prefix, text = line:match('^([-+:$*])(.+)')
            local mtype = mtypes[prefix]

            if not prefix or not text  then
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                return -1
            end

            assert(prefix and text, 'unrecognized line: '..line)
            assert(mtype, 'unrecognized message type: '..prefix)

            if prefix == '*' then -- multi-bulk, contains multiple sub-messages
                local replies = tonumber(text)
                local old_offset = offset

                local child = parent:add(proto, buffer(offset, 1), 'Redis '..mtype..' Reply')
                child:add(f.bulk_reply_num, buffer(offset + 1, length - 1))

                offset = offset + length + CRLF

                -- recurse down for each message contained in this multi-bulk message
                for ii = 1, replies do
                    offset = recurse(child, buffer, offset)
                    if offset == -1 then
                        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                        return -1
                    end
                end
                child:set_len(offset - old_offset)

            elseif prefix == '$' then -- bulk, contains one binary string
                local bytes = tonumber(text)
                
                if bytes == -1 then
                    local child = parent:add(proto, buffer(offset, length + CRLF),
                                             'Redis '..mtype..' Reply')

                    offset = offset + length + CRLF

                    child:add(f.value, '<null>')
                else
                    if(buffer:len() < offset + length + CRLF + bytes + CRLF) then
                        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                        return -1
                    end

                    local child = parent:add(proto, buffer(offset, length + CRLF + bytes + CRLF),
                                             'Redis '..mtype..' Reply')
                    -- add size
                    child:add(f.size, buffer(offset + 1, length - 1))

                    offset = offset + length + CRLF

                    -- get the string contained within this bulk message
                    child:add(f.value, buffer(offset, bytes))
                    offset = offset + bytes + CRLF

                end
            else -- integer, status or error
                local child = parent:add(proto, buffer(offset, length + CRLF),
                                         'Redis '..mtype..' Reply')
                child:add(f.value, buffer(offset + prefix:len(), length - prefix:len()))
                offset = offset + length + CRLF
            end

            return offset
        end

        -- parse top-level messages until the buffer is exhausted
        local offset = 0
        while offset < buffer():len() do
            offset = recurse(tree, buffer, offset)
            if offset < 0 then
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                return
            end
        end

        -- check that we consumed exactly the right number of bytes
--        assert(offset == buffer():len(), 'consumed '..offset..' bytes of '..buffer():len())
    end

    -- register this dissector for the standard Redis ports
    local dissectors = DissectorTable.get('tcp.port')
    for _, port in ipairs{ 6379, } do
        dissectors:add(port, proto)
    end
end
