# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(priority-donate-sema-2) begin
(priority-donate-sema-2) Initializing lock.
(priority-donate-sema-2) Initializing semaphore to 0.
(priority-donate-sema-2) Creating a low priority thread.
(priority-donate-sema-2) Low priority thread now acquiring lock.
(priority-donate-sema-2) Low priority thread now downing semaphore.
(priority-donate-sema-2) Creating a high priority thread.
(priority-donate-sema-2) High priority thread waiting to acquire lock.
(priority-donate-sema-2) Creating a medium priority thread.
(priority-donate-sema-2) Medium priority thread now downing semaphore.
(priority-donate-sema-2) Upping semaphore.
(priority-donate-sema-2) Low priority thread now releasing lock.
(priority-donate-sema-2) High priority thread now releasing lock.
(priority-donate-sema-2) High priority thread exiting.
(priority-donate-sema-2) Low priority thread now upping semaphore.
(priority-donate-sema-2) Medium priority thread now upping semaphore.
(priority-donate-sema-2) Medium priority thread now exiting.
(priority-donate-sema-2) Low priority thread exiting.
(priority-donate-sema-2) end
EOF
pass;
