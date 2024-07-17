#!/bin/bash
echo "Restore action script called with arguments: " >>/tmp/restore_action.log
env >>/tmp/criu/service/restore_action.log
