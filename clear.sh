#!/bin/sh

files=$(find . -type f -name "*.bak" 2>/dev/null)
if [ -z "$files" ]; then
    echo "未找到任何 .bak 文件。"
    exit 0
fi

echo "以下 .bak 文件将被删除："
echo "$files"
printf "确认删除这些文件吗？(y/n) "
read reply

case "$reply" in
    [Yy]*)
        echo "$files" | xargs rm -f
        echo "删除完成。"
        ;;
    *)
        echo "操作已取消。"
        ;;
esac