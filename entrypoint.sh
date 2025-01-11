#!/bin/sh

LOCKFILE="/tmp/process_lockfile.lock"
LOGFILE="process_log.txt"

# Kiểm tra và tạo lockfile
exec 200>$LOCKFILE
flock -n 200 || { echo "Another process is running. Exiting."; exit 1; }

# Ghi log vào file log
echo "Starting file processing..." >> $LOGFILE

# Xóa thư mục log nếu có
rm -rf log/

# Process safe files sequentially
echo "Processing safe files:" >> $LOGFILE
for file in file/safe/*; do
    echo "Processing safe file: $file" >> $LOGFILE
    ./sandbox "$file" >> $LOGFILE 2>&1
    echo "Finished processing safe file: $file" >> $LOGFILE
done

# Process dangerous files sequentially
echo "Processing dangerous files:" >> $LOGFILE
for file in file/dangerous/*; do
    echo "Processing dangerous file: $file" >> $LOGFILE
    ./sandbox "$file" >> $LOGFILE 2>&1
    echo "Finished processing dangerous file: $file" >> $LOGFILE
done

echo "All files processed." >> $LOGFILE

# Giải phóng lockfile sau khi hoàn thành
flock -u 200
