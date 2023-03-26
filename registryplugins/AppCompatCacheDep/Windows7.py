import datetime
import logging
import codecs

def Windows7(raw_bytes, is_32bit, control_set):
    # initialize the starting index and control set
    index = 4
    control_set = control_set

    # get the number of cache entries
    entry_count = int.from_bytes(raw_bytes[4:8], byteorder="little")

    # set the starting index and position
    index = 128
    position = 0

    # set the null date for FILETIME
    FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)

    # if there are no cache entries, return None
    if entry_count == 0:
        return
    
    # loop through the cache entries
    while index < len(raw_bytes):
        try:
            # initialize the cache entry dictionary
            cache_entry = {}

            # get the path size
            cache_entry["path_size"] = int.from_bytes(raw_bytes[index:index+2], byteorder="little", signed=False)
            index += 2
    
            # get the max path size
            max_path_size = int.from_bytes(raw_bytes[index:index+2], byteorder="little", signed=False)
            index += 2
            
            # get the path offset
            if not is_32bit:
                index += 4
                path_offset = int.from_bytes(raw_bytes[index:index+8], byteorder="little", signed=False)
                index += 8
            else:
                path_offset = int.from_bytes(raw_bytes[index:index+4], byteorder="little")
                index += 4
    
            # get the last modified time
            try:
                timestamp = int.from_bytes(raw_bytes[index:index + 8], "little") / 10  # divide by 10 to convert 100-nanosecond intervals to microseconds
                cache_entry["last_modified_time_utc"] = str(FILETIME_null_date + datetime.timedelta(microseconds=timestamp))
                if '1601' in cache_entry["last_modified_time_utc"]:
                    cache_entry["last_modified_time_utc"] = ""
            except Exception as e:
                cache_entry["last_modified_time_utc"] = ""
                
            index += 8

            # get the insertion flags
            cache_entry["insert_flags"] = int.from_bytes(raw_bytes[index:index+4], byteorder="little")
            index += 4
            
            # skip 4 unknown (shim flags?)
            index += 4
            
            # get the cache entry data size and offset
            if not is_32bit:
                cache_entry_data_size = int.from_bytes(raw_bytes[index:index+8], byteorder="little", signed=False)
                index += 8
                data_offset = int.from_bytes(raw_bytes[index:index+8], byteorder="little", signed=False)
                index += 8
            else:
                cache_entry_data_size = int.from_bytes(raw_bytes[index:index+4], byteorder="little", signed=False)
                index += 4
                data_offset = int.from_bytes(raw_bytes[index:index+4], byteorder="little", signed=False)
                index += 4
            
            # decode the path
            cache_entry["path"] = codecs.decode(
                raw_bytes[path_offset:path_offset+cache_entry["path_size"]], "utf-16le"
            ).replace("\\??\\", "")
            
            # get the execution flag
            if cache_entry["insert_flags"] & 0x01:
                cache_entry["executed"] = "Yes"
            else:
                cache_entry["executed"] = "No"
                
            cache_entry["cache_entry_position"] = position
            cache_entry["control_set"] = control_set
            
            position += 1
            
            result = (
                    cache_entry.get('control_set', ""),
                    cache_entry.get('cache_entry_position', ""),
                    cache_entry.get('path', ""),
                    cache_entry.get('last_modified_time_utc', ""),
                    cache_entry.get('executed', ""),
                )
            yield result
            
            if entry_count == position:
                break
        except Exception as ex:
            logging.error(
                f"Error parsing cache entry. Position: {position} Index: {index}, Error: {str(ex)}")
            if len(entries) < entry_count:
                raise
            break
