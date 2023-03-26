import datetime
import codecs

def Windows10(raw_bytes, control_set):
    expected_entries = 0

    offset_to_records = int.from_bytes(raw_bytes[:4], "little")
    expected_entries = int.from_bytes(raw_bytes[0x24:0x28], "little")

    if offset_to_records == 0x34:
        expected_entries = int.from_bytes(raw_bytes[0x28:0x2C], "little")

    index = offset_to_records
    
    control_set = control_set
    
    position = 0
    
    FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
    

    while index < len(raw_bytes):
        try:
            cache_entry = {}
            
            cache_entry["signature"] = codecs.decode(raw_bytes[index:index + 4], "ascii")
            index += 4

            if cache_entry["signature"] != "10ts":
                break

            index += 4

            cache_entry_data_size = int.from_bytes(raw_bytes[index:index + 4], "little", signed=False)
            index += 4

            cache_entry["path_size"] = int.from_bytes(raw_bytes[index:index + 2], "little", signed=False)
            index += 2

            cache_entry["path"] = codecs.decode(
                raw_bytes[index:index + cache_entry["path_size"]], "utf-16le"
            ).replace("\\??\\", "")
                
            index += cache_entry["path_size"]

            try:
                timestamp = int.from_bytes(raw_bytes[index:index + 8], "little") / 10  # divide by 10 to convert 100-nanosecond intervals to microseconds
                cache_entry["last_modified_time_utc"] = str(FILETIME_null_date + datetime.timedelta(microseconds=timestamp))
                if '1601' in cache_entry["last_modified_time_utc"]:
                    cache_entry["last_modified_time_utc"] = ""
            except:
                cache_entry["last_modified_time_utc"] = ""
            
            index += 8

            cache_entry["data_size"] = int.from_bytes(raw_bytes[index:index + 4], "little")
            index += 4

            cache_entry["data"] = raw_bytes[index:index + cache_entry["data_size"]]
            index += cache_entry["data_size"]

            # if the last 4 bytes of data is 1, it indicates execution
            cache_entry["executed"] = (
                "Yes"
                if int.from_bytes(cache_entry["data"][-4:], "little") == 1
                else "No"
            )

            cache_entry["control_set"] = control_set
            cache_entry["cache_entry_position"] = position

            position += 1
            result = (
                    cache_entry.get('control_set', ""),
                    cache_entry.get('cache_entry_position', ""),
                    cache_entry.get('path', ""),
                    cache_entry.get('last_modified_time_utc', ""),
                    cache_entry.get('executed', ""),
                )
            yield result
        except Exception as ex:
            print(f"Error parsing cache entry. Position: {position} Index: {index}, Error: {str(ex)} ")
            continue
