-- Deklaracia protokolu

my_protocol = Proto("ISA", "ISA Protocol")


message = ProtoField.string("my_protocol.message", "Message raw")
message_length = ProtoField.int32("my_protocol.message_length", "Length of data", base.DEC)
message_sender = ProtoField.string("my_protocil.message_sender", "Sender")
server_status = ProtoField.string("my_protocol.server_status", "Server status")

recipient = ProtoField.string("my_protocol.recipient", "Recipient")
subject = ProtoField.string("my_protocol.subject", "Subject")
body = ProtoField.string("my_protocol.body", "Body of msg")
from = ProtoField.string("my_protocol.from", "From")

my_protocol.fields = {
    message,
    message_length,
    message_sender,
    server_status,
    recipient,
    subject,
    body,
    from
}

-- Funkcia ktora vrati cast spravy ktora je v uvozdzovkach
-- nazaklade toto ktora cast je vybrana pomocou "which_part"
function get_part_of_msg(buffer, which_part)
    cnt = 0
    print_off = 0
    word = ""
    for one_char in (buffer(0, length):string()):gmatch"." do

        if one_char == '"' 
        then             -- ked narazi na uvodzoku ulozi string 
            cnt = cnt + 1
            print_off = 1
        else print_off = 0
        end

        if (cnt == (2*which_part - 1)) and (print_off == 0)  
        then
            word = word .. one_char
        end
        
    end

    return word
end

-- Funkcia ktora vrati ake cislo fetch bolo zadane
function get_number_of_fetch(buffer)
    print_on = 0
    cnt = 0
    number = ""
    for one_char in (buffer(0, length):string()):gmatch"." do
        if one_char == " " 
        then
            cnt = cnt + 1
        end

        if (print_on == 1 and one_char ~= ")") 
        then
            number = number .. one_char
        end

        if cnt == 2 
        then
            print_on = 1
        end
    
    end

    return number
end


-- Funkcia ktora vrati pocet sprav 
function get_number_of_msg(buffer)
    cnt = 0
    
    for one_char in (buffer(0, length):string()):gmatch"." do
        if one_char == "\""
        then
            cnt = cnt + 1
        end 
    end

    return (cnt / 4)
end

-- Funkcia ktora skontrolu je prisela cela sprava
function check_len_of_msg(buffer)
    left_bracket = 0
    right_bracket = 0
    
    result = false

    for one_char in (buffer(0, length):string()):gmatch"." do
        if one_char == "(" then
            left_bracket = left_bracket + 1
        end

        if one_char == ")" then
            right_bracket = right_bracket + 1
        end
    end

    if (left_bracket == right_bracket) and (left_bracket ~= 0) 
    then
        result = true
    else
        result = false
    end

    return result
end


-- vytvorenie dissectora
-- tato cast bola prebrata a modifikovana z stranky
    -- https://gitlab.com/wireshark/wireshark/-/wikis/Lua/Dissectors
function my_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    result = false

    if length == 0 then return end
    
    pinfo.cols.protocol = "ISA"

    -- osetrenie reassembly 
    while (1)
    do 
        result = check_len_of_msg(buffer)
        if result == true then
            break
        else
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            break
        end
    end

    local subtree = tree:add(my_protocol, buffer(), "ISA Protocol Data")

    -- o akeho odosielatela sa jedna (server || klient)
    if (string.find(buffer(1,3):string(), "ok") ~= nil) or (string.find(buffer(1,3):string(), "err") ~= nil)
    then                                    -- sprava od serveru
        pinfo.cols.info:set("Response: ")
        subtree:add(message_sender, "server")
        
        -- vypisanie statusu servera
        if string.find(buffer(1,3):string(), "ok") ~= nil
        then
            subtree:add(server_status, "ok")
            msg_info_tree = subtree:add(my_protocol, "Message info")
            -- response REGISTER
            if string.find(get_part_of_msg(buffer, 1), "registered") ~= nil
            then
                pinfo.cols.info:append(get_part_of_msg(buffer, 1))
            end

            -- response LOGIN
            if string.find(get_part_of_msg(buffer, 1), "logged in") ~= nil
            then
                pinfo.cols.info:append("logged in " .. get_part_of_msg(buffer,2))
            end

            -- response SEND
            if string.find(get_part_of_msg(buffer, 1), "sent") ~= nil
            then
                pinfo.cols.info:append(get_part_of_msg(buffer, 1))
            end

            -- response LIST
            if (string.find(buffer(0, length):string(), "ok %(") ~= nil) and (string.find(buffer(0, length):string(), "%(\"") == nil)
            then
                pinfo.cols.info:append("listed " .. get_number_of_msg(buffer) .. " messages")
            end

            -- response FETCH
            -- fetch je vzdy v tvare (" ... ")
            if (string.find(buffer(0, length):string(), "%(\"") ~= nil) and (string.find(buffer(0, length):string(), "\"%)") ~= nil)
            then
                pinfo.cols.info:append("fetch [From: " .. get_part_of_msg(buffer, 1))
                msg_info_tree:add(from, get_part_of_msg(buffer, 1))

                pinfo.cols.info:append(", Subject: " .. get_part_of_msg(buffer, 2) .. "]")
                msg_info_tree:add(subject, get_part_of_msg(buffer, 2))

                msg_info_tree:add(body, get_part_of_msg(buffer, 3))
            end

            -- response LOGOUT
            if string.find(get_part_of_msg(buffer, 1), "logged out") ~= nil
            then
                pinfo.cols.info:append("logget out")
            end
        else
            subtree:add(server_status, "err")
            msg_info_tree = subtree:add(my_protocol, "Message info")
            pinfo.cols.info:append("error -> " .. get_part_of_msg(buffer, 1))
        end

    else                                    -- sprava od klienta
        pinfo.cols.info:set("Request: ")
        subtree:add(message_sender, "client")
        
        msg_info_tree = subtree:add(my_protocol, "Message info")

        -- request REGISTER
        if string.find(buffer(0, length):string(), "register") ~= nil
        then
            pinfo.cols.info:append("register " .. get_part_of_msg(buffer, 1))
        end

        -- request LOGIN
        if string.find(buffer(0, length):string(), "login") ~= nil
        then
            pinfo.cols.info:append("login " .. get_part_of_msg(buffer, 1))
        end

        -- request SEND
        if string.find(buffer(0, length):string(), "send") ~= nil
        then
            pinfo.cols.info:append("send [Recipient: " .. get_part_of_msg(buffer, 2))
            msg_info_tree:add(recipient, get_part_of_msg(buffer, 2))

            pinfo.cols.info:append(", Subject: " .. get_part_of_msg(buffer, 3) .. "]")
            msg_info_tree:add(subject, get_part_of_msg(buffer, 3))

            msg_info_tree:add(body, get_part_of_msg(buffer, 4))

        end

        -- request LIST
        if string.find(buffer(0, length):string(), "list") ~= nil
        then
            pinfo.cols.info:append("list " .. get_part_of_msg(buffer, 1))
        end

        -- request FETCH
        if string.find(buffer(0, length):string(), "fetch") ~= nil
        then
            number_fetch = get_number_of_fetch(buffer(0, length))
            pinfo.cols.info:append("fetch " .. number_fetch)   -- vypise cislo fetch
        end

        -- request LOGOUT
        if string.find(buffer(0, length):string(), "logout") ~= nil
        then
            pinfo.cols.info:append("logout " .. get_part_of_msg(buffer, 1))
        end

    end


    msg_info_tree:add(message, buffer(0,length))
    msg_info_tree:add(message_length, length)

end 

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(32323, my_protocol)
