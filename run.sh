#!/usr/bin/env bash

# Open sender in a new shell
gnome-terminal -- bash -c ./output/sender > sender.log 2>&1 &
echo "Sender launched in a new shell."

# Open receiver in a new shell
gnome-terminal -- bash -c ./output/receiver > receiver.log 2>&1 &
echo "Receiver launched in a new shell."

# No waiting needed since processes run in separate terminals"

