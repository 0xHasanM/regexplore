import datetime
import logging
import codecs

def WindowsXP(raw_bytes, is_32bit, control_set):
    # initialize the starting index and control set
    index = 4
    control_set = control_set

    # get the number of cache entries
    entry_count = int.from_bytes(raw_bytes[4:8], byteorder="little")

    # set the starting index and position
    index = 400
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

            # set the path size
            cache_entry["path_size"] = 528
    
            cache_entry['path'] = cache_entry["path"] = codecs.decode(
                raw_bytes[index:index + cache_entry["path_size"]], "utf-16le"
            ).replace("\\??\\", "")
            
            index += 528
            
            try:
                timestamp = int.from_bytes(raw_bytes[index:index + 8], "little") / 10  # divide by 10 to convert 100-nanosecond intervals to microseconds
                cache_entry["last_modified_time_utc"] = str(FILETIME_null_date + datetime.timedelta(microseconds=timestamp))
                if '1601' in cache_entry["last_modified_time_utc"]:
                    cache_entry["last_modified_time_utc"] = ""
            except:
                cache_entry["last_modified_time_utc"] = ""
                
            index += 8
            
            cache_entry['file_size'] =  int.from_bytes(raw_bytes[index:index + 8], "little", signed=False)
            
            index += 8
            
            index += 8
            
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
