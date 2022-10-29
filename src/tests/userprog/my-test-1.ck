# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(my-test-1) begin
my-test-1: exit(-1)
EOF
pass;
