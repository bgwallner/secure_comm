#!/usr/bin/env bash

# Open sender in a new shell
gnome-terminal -- bash -c ./output/sender &
echo "Sender launched in a new shell."

# Open receiver in a new shell
gnome-terminal -- bash -c ./output/receiver &
echo "Receiver launched in a new shell."

# No waiting needed since processes run in separate terminals"

