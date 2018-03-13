-- Wireshark packet dissector for Redis
-- Protocol specification: http://redis.io/topics/protocol
-- Written by John Zwinck, 29 November 2011

do -- scope
    local proto = Proto('redis', 'Redis')

    local f = proto.fields
    -- we could make more of these, e.g. to distinguish keys from values
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

        -- recursively parse and generate a tree of data from messages in a packet
        -- parent: the tree root to populate under
        -- buffer: the entire packet buffer
        -- offset: the current offset in the buffer
        -- matches: a one-pass generator function which yields parsed lines from the packet
        -- returns: the new offset (i.e. the input offset plus the number of bytes consumed)
        local function recurse(parent, buffer, offset, matches)
            local line = matches() -- get next line
            local length = line:len()
            local prefix, text = line:match('([-+:$*])(.+)')
            local mtype = mtypes[prefix]

            assert(prefix and text, 'unrecognized line: '..line)
            assert(mtype, 'unrecognized message type: '..prefix)

            if prefix == '*' then -- multi-bulk, contains multiple sub-messages
                local replies = tonumber(text)

                -- this is a bit gross: we parse (part of) the buffer again to
                -- calculate the length of the entire multi-bulk message
                -- if we don't do this, Wireshark will highlight only our prologue
                local bytes = 0
                local remainder = buffer():string():sub(offset + length + CRLF)
                local submatches = remainder:gmatch('[^\r\n]+')

                local child = parent:add(proto, 'Redis '..mtype..' Reply')
                offset = offset + length + CRLF

                -- recurse down for each message contained in this multi-bulk message
                for ii = 1, replies do
                    offset = recurse(child, buffer, offset, matches)
                end

            elseif prefix == '$' then -- bulk, contains one binary string
                local bytes = tonumber(text)
                
                if bytes == -1 then
                    local child = parent:add(proto, buffer(offset, length + CRLF),
                                             'Redis '..mtype..' Reply')

                    offset = offset + length + CRLF

                    child:add(f.value, '<null>')
                else
                    local child = parent:add(proto, buffer(offset, length + CRLF + bytes + CRLF),
                                             'Redis '..mtype..' Reply')

                    offset = offset + length + CRLF

                    -- get the string contained within this bulk message
                    local line = matches()
                    local length = bytes
                    child:add(f.value, buffer(offset, bytes))
                    offset = offset + length + CRLF
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
        local matches = buffer():string():gmatch('[^\r\n]+')
        local offset = 0
        while offset < buffer():len() do
            offset = recurse(tree, buffer, offset, matches)
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
