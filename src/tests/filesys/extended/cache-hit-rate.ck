# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-hit-rate) begin
(cache-hit-rate) create "hitrate"
(cache-hit-rate) open "hitrate"
(cache-hit-rate) write "hitrate"
(cache-hit-rate) close "hitrate"
(cache-hit-rate) open "hitrate"
(cache-hit-rate) read "hitrate"
(cache-hit-rate) close "hitrate"
(cache-hit-rate) open "hitrate"
(cache-hit-rate) read "hitrate"
(cache-hit-rate) close "hitrate"
(cache-hit-rate) reread hit rate greater than cold hit rate
(cache-hit-rate) end
EOF
pass;
