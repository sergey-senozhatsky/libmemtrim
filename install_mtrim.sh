#!/bin/sh

#
# Copyright (C) 2017 Sergey Senozhatsky
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301 USA
#

MTRIM_PATH=./build/lib/

function remount_rootfs_rw
{
	if [ $1 -eq 0 ]; then
		return 0
	fi

	sync

	mount -o remount,rw /
	if [ $? != 0 ]; then
		echo "Can't remount rootfs"
		exit 6
	fi
}

function remount_rootfs_ro
{
	if [ $1 -eq 0 ]; then
		return 0
	fi

	sync

	mount -o remount,ro /
	if [ $? != 0 ]; then
		echo "Can't remount rootfs"
		exit 6
	fi
}

function install
{
	local path=$1
	local remount=$2

	if [ "z$path" == "z" ]; then
		echo "No application path was provided"
		exit 1
	fi

	if [ ! -e $path ]; then
		echo "Unknown application $path"
		exit 2
	fi

	if [ -e $path"_" ]; then
		echo "mtrim backup file already exists"
		exit 4
	fi

	if [ ! -e $MTRIM_PATH/libmtrim.so ]; then
		echo "No libmtrim.so file found at $MTRIM_PATH"
		exit 5
	fi

	remount_rootfs_rw $remount

	mv $path $path"_"

cat << EOF > $path
#/bin/sh

LD_PRELOAD=${MTRIM_PATH}/libmtrim.so MTRIM_TIMEOUT=30 MTRIM_KEEPCOST_THRESHOLD=40k MTRIM_FREEBLKS_THRESHOLD=2M MTRIM_DEBUG=1 ${path}_ "\$@"

EOF

	chmod +x $path

	remount_rootfs_ro $remount

	return 0
}

function uninstall
{
	local path=$1
	local remount=$2

	if [ "z$path" == "z" ]; then
		echo "No application path was provided"
		exit 1
	fi

	if [ ! -e $path ]; then
		echo "Unknown application $path"
		exit 2
	fi

	if [ ! -e ${path}_ ]; then
		echo "No mtrim backup file was found"
		exit 4
	fi

	remount_rootfs_rw $remount

	rm $path
	mv $path"_" $path

	remount_rootfs_ro $remount

	return 0
}

function process
{
	if [ "z$1" == "zinstall" -o "z$1" == "zrinstall" ]; then
		local remount=0

		if [ "z$1" == "zrinstall" ]; then
			remount=1
		fi

		install $2 $remount
		return $?
	fi

	if [ "z$1" == "zuninstall" -o "z$1" == "zruninstall" ]; then
		local remount=0

		if [ "z$1" == "zruninstall" ]; then
			remount=1
		fi

		uninstall $2 $remount
		return $?
	fi

	return 7
}

function print_usage
{
	echo "Usage example:"
	echo "install_hook.sh install|uninstall /path/application"
	echo "                rinstall|runinstall - to force remount of FS in rw mode"
}

hook_args=("$@")
hook_args_num=${#hook_args[@]}

if [ $hook_args_num -le 1 ]; then
	print_usage
	exit 3
fi

for (( i=1; i<${hook_args_num}; i++ )); do
	process ${hook_args[0]} ${hook_args[$i]}
	code=$?
	if [ $code != 0 ]; then
		print_usage
		exit $code
	fi
done

exit 0
