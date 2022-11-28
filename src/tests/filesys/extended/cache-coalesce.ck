# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-coalesce) begin
(cache-coalesce) create "coalesce"
(cache-coalesce) open "coalesce"
(cache-coalesce) writing "coalesce"
(cache-coalesce) close "coalesce"
(cache-coalesce) open "coalesce"
(cache-coalesce) close "coalesce"
(cache-coalesce) write count on the order of 128
(cache-coalesce) end
EOF
pass;
