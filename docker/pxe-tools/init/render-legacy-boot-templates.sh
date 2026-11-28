#!/bin/bash
# Source from bootstrap-render-templates.sh in the legacy appliance.
render preseed.php.j2      "$HTTP_ROOT/preseed.php"
render grub.php.j2         "$HTTP_ROOT/grub.php"
