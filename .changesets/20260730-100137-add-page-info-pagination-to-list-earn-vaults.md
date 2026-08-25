---
module: "root"
bump: "minor"
title: "Add page_info pagination to list_earn_vaults"
date: "2026-07-30"
---

list_earn_vaults now returns a page_info block (has_next_page/has_previous_page plus opaque start/end cursors) and accepts opaque keyset cursors.
