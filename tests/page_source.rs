//! The status page as source. No browser runs here, so each test checks that a feature is still
//! in the page: the element ids it draws into, the routes it calls and the words it shows. A
//! reflow of the CSS or a rename of a script function must not break any of them.
//! `web_e2e` has the one test that the server sends this exact text.

const PAGE: &str = include_str!("../src/web/index.html");

/// The page's ceiling, raised on purpose for the redesign: static bytes in the binary, no memory
/// at run time.
const PAGE_HARD_CAP_BYTES: usize = 80 * 1024;

/// The redesign: card descriptions that say what each setting does, save-at-once settings and a
/// notice line; raised on purpose, never past the cap.
const PAGE_BUDGET_BYTES: usize = 72 * 1024;

fn assert_page_has(needles: &[&str]) {
    for needle in needles {
        assert!(PAGE.contains(needle), "the page lacks {needle}");
    }
}

fn assert_page_has_ids(ids: &[&str]) {
    for id in ids {
        assert!(
            PAGE.contains(&format!("id=\"{id}\"")),
            "the page lacks #{id}"
        );
    }
}

/// True when one line of the page holds both parts.
fn a_line_has(first: &str, second: &str) -> bool {
    PAGE.lines()
        .any(|line| line.contains(first) && line.contains(second))
}

#[test]
fn the_page_is_small_and_self_contained() {
    assert!(
        PAGE.len() <= PAGE_BUDGET_BYTES,
        "this slice's budget is {PAGE_BUDGET_BYTES} bytes, the page has {}",
        PAGE.len()
    );
    assert!(
        PAGE.len() <= PAGE_HARD_CAP_BYTES,
        "the hard cap is {PAGE_HARD_CAP_BYTES} bytes, the page has {}",
        PAGE.len()
    );
    for external in [
        "src=", "href=", "http://", "https://", "url(", "@import", "<link",
    ] {
        assert!(!PAGE.contains(external), "the page refers to {external}");
    }

    // Names come from the network: the page never builds markup from them.
    assert!(!PAGE.contains("innerHTML") && !PAGE.contains("insertAdjacentHTML"));
}

#[test]
fn the_page_fits_a_phone_and_dark_mode() {
    assert_page_has(&["prefers-color-scheme: dark", "name=\"viewport\""]);
}

#[test]
fn the_page_calls_every_route_of_the_api() {
    assert_page_has(&[
        "/api/status",
        "/api/querylog",
        "/api/pause",
        "/api/resume",
        "/api/lists/refresh",
        "/api/update",
        "/api/login",
        "/api/logout",
        "/api/cache/clear",
        "/api/stats/clear",
        "/api/querylog/clear",
        "/api/history?days=",
        "/api/rules",
        "/api/rules/remove",
        "/api/explain?name=",
        "/api/settings",
        "/api/services",
        "\"/api/lists\"",
        "/api/lists/add",
        "/api/lists/reset",
        // The list route is the prefix plus "edit" or "remove".
        "\"/api/lists/\"",
        "\"edit\"",
        "\"remove\"",
        // Without it every 401 would open the browser's own sign-in prompt.
        "\"X-Requested-With\": \"picoguard\"",
    ]);
}

#[test]
fn the_pause_buttons_offer_five_minutes_to_a_day() {
    for minutes in ["5", "30", "60", "1440"] {
        assert!(
            PAGE.contains(&format!("data-minutes=\"{minutes}\"")),
            "{minutes}"
        );
    }
}

#[test]
fn the_page_signs_in_with_its_own_form_and_never_asks_for_the_browser_prompt() {
    assert_page_has_ids(&[
        "login-form",
        "login-user",
        "login-password",
        "login-note",
        "logout",
    ]);
    assert_page_has(&[
        "type=\"password\"",
        "autocomplete=\"current-password\"",
        "class=\"signed-out\"",
        "\"X-Requested-With\": \"picoguard\"",
        "Session ended, sign in again.",
    ]);
}

/// A tab is a `[data-tab]` button and a `[data-panel]` panel, and no element id equals a tab
/// name, so a fragment never scrolls.
#[test]
fn the_page_has_four_tabs_kept_in_the_url_fragment() {
    assert_page_has(&["role=\"tablist\"", "aria-selected", "\"hashchange\""]);

    for tab in ["dashboard", "log", "lists", "settings"] {
        assert!(PAGE.contains(&format!("data-tab=\"{tab}\"")), "{tab}");
        assert!(PAGE.contains(&format!("id=\"panel-{tab}\"")), "{tab}");
        assert!(
            !PAGE.contains(&format!("id=\"{tab}\"")),
            "{tab} is a fragment target"
        );
    }
}

/// A hidden page does not poll, and a tab's own data is fetched only while that tab is open.
#[test]
fn the_page_polls_one_update_at_a_time_and_fetches_only_the_open_tabs_data() {
    assert_page_has(&[
        "setInterval(update, 5000)",
        "polling",
        "pollAgain",
        "document.hidden",
        "visibilitychange",
    ]);

    for (panel, route) in [
        ("panel-log", "/api/querylog?limit=50"),
        ("panel-lists", "/api/rules"),
        ("panel-settings", "/api/settings"),
    ] {
        assert!(
            a_line_has(panel, route),
            "{route} is not tied to the {panel} panel"
        );
    }

    let on_hashchange = PAGE.split("\"hashchange\"").nth(1).unwrap();
    assert!(
        on_hashchange
            .split("});")
            .next()
            .unwrap()
            .contains("update();")
    );
}

/// The pause countdown counts the seconds the board says are left, not the board's clock
/// against the browser's.
#[test]
fn the_pause_countdown_uses_the_seconds_left_not_the_boards_clock() {
    assert_page_has(&["seconds_left"]);
    assert!(!PAGE.contains("pause.until"));
}

/// The read-only view leaves the field out, so the card is hidden there with the top lists.
#[test]
fn the_dashboard_has_an_upstreams_card_drawn_as_text() {
    assert_page_has_ids(&["upstreams", "upstream-table"]);
    assert_page_has(&["local: ", "Answered"]);
}

#[test]
fn the_dashboard_has_a_cache_card_with_a_confirmed_clear_button() {
    assert_page_has_ids(&["cache", "cache-size", "clear-cache", "cache-note"]);
    assert_page_has(&[
        "\"/api/cache/clear\"",
        "Cache cleared (",
        "Clear the DNS cache?",
    ]);
}

#[test]
fn the_dashboard_lists_the_top_clients() {
    assert_page_has_ids(&["top-queried", "top-blocked", "top-clients"]);
}

#[test]
fn the_query_log_rows_offer_block_allow_and_why() {
    assert_page_has(&[
        "data-act",
        "\"Block\"",
        "\"Allow\"",
        "\"Why\"",
        "blocked_response",
        "\"/api/rules\"",
        "location.hash",
    ]);
    assert_page_has_ids(&["check-name"]);
}

#[test]
fn the_lists_tab_has_your_rules_and_a_name_check() {
    assert_page_has_ids(&[
        "rules",
        "rule-count",
        "rule-table",
        "config-rules",
        "check",
        "check-form",
        "check-name",
        "check-result",
    ]);
    assert_page_has(&["\"/api/rules/remove\"", "/api/explain?name="]);
}

#[test]
fn the_lists_tab_turns_lists_on_and_off_adds_removes_and_resets_them_and_shows_the_memory() {
    assert_page_has_ids(&[
        "lists-from",
        "list-table",
        "list-memory",
        "list-add",
        "list-form",
        "l-name",
        "l-url",
        "l-role",
        "l-hours",
        "list-add-note",
        "lists-reset",
        "settings-memory",
    ]);
    assert_page_has(&[
        "\"/api/lists/add\"",
        "\"/api/lists/reset\"",
        "enabled",
        "refresh_hours",
        "from the config file",
        "Set on this page",
        "Reset to config file",
        "Memory estimate: ",
        "Remove this list?",
    ]);
}

/// Its cards come with the parts that apply them; this part shows where settings are saved and
/// why a saved file is not used.
#[test]
fn the_settings_tab_says_where_settings_are_saved_and_why_they_are_not_used() {
    assert_page_has_ids(&[
        "tab-settings",
        "settings-note",
        "settings-file",
        "rules-note",
    ]);
    assert_page_has(&[
        "\"/api/settings\"",
        "Saved settings could not be used: ",
        "Saving from this page replaces them.",
        "can_save",
    ]);
}

/// Each card says where its values come from, goes back to the config file, and saves on its
/// own.
#[test]
fn the_settings_tab_edits_the_upstream_servers_and_the_cache() {
    assert_page_has_ids(&[
        "upstream-card",
        "upstream-from",
        "upstream-list",
        "upstream-add",
        "upstream-new",
        "bootstrap",
        "upstream-reset",
        "upstream-note",
        "cache-card",
        "cache-from",
        "c-entries",
        "c-kib",
        "c-min",
        "c-max",
        "c-optimistic",
        "cache-reset",
        "cache-note",
    ]);
    assert_page_has(&[
        "From the config file",
        "Changed on this page",
        "Reset to config file",
        "A change clears the cache.",
        "data-reset=\"upstream\"",
        "data-reset=\"cache\"",
        "Move up",
        "Move down",
        "\"Remove\"",
        "max_bytes",
    ]);
}

#[test]
fn the_settings_tab_edits_the_rewrites_and_safe_search() {
    assert_page_has_ids(&[
        "rewrites-card",
        "rewrites-from",
        "rewrite-table",
        "rewrite-add",
        "rewrite-name",
        "rewrite-answer",
        "rewrites-reset",
        "rewrites-note",
        "safe-search-card",
        "safe_search-from",
        "safe-search",
        "safe_search-reset",
        "safe_search-note",
    ]);
    assert_page_has(&["rewrites", "safe_search", "rewritten"]);
}

#[test]
fn the_settings_tab_switches_blocked_services_by_group_with_a_filter() {
    assert_page_has_ids(&[
        "services-card",
        "services-from",
        "service-filter",
        "services-state",
        "service-groups",
        "services-reset",
        "services-note",
    ]);
    assert_page_has(&["\"/api/services\"", "services", "AdGuard"]);
}

/// The SVG namespace is read from the markup, because its literal contains `http://`, which the
/// page must never contain.
#[test]
fn the_chart_is_inline_svg_drawn_with_create_element_ns() {
    assert_page_has(&["<svg id=\"chart\"", "createElementNS(", ".namespaceURI"]);
    assert_page_has_ids(&["chart-readout"]);
}

#[test]
fn the_chart_has_four_ranges_that_keep_to_the_retention_and_are_remembered() {
    for days in ["1", "7", "30", "90"] {
        assert!(PAGE.contains(&format!("data-days=\"{days}\"")), "{days}");
    }

    assert_page_has_ids(&["chart-totals", "chart-title"]);
    assert_page_has(&[
        "retention_days",
        "&offset=",
        "localStorage.getItem(",
        "localStorage.setItem(",
        "since ",
    ]);

    // Storage can be blocked: each use of it sits in a try.
    assert!(PAGE.matches("try {").count() >= 2);
    assert!(!PAGE.contains("(since start)"));
}

#[test]
fn the_statistics_card_and_the_clear_buttons_ask_before_they_clear() {
    assert_page_has_ids(&[
        "stats-card",
        "retention",
        "stats-saving",
        "stats-clear",
        "stats-reset",
        "clear-log",
    ]);
    assert_page_has(&[
        "Clear the statistics?",
        "\"/api/stats/clear\"",
        "Clear the query log?",
        "\"/api/querylog/clear\"",
    ]);

    for option in ["1", "7", "30", "90"] {
        assert!(
            PAGE.contains(&format!("<option value=\"{option}\">")),
            "{option}"
        );
    }
}

/// `pause_takes_one_to_1440_minutes_and_nothing_else` pins the same limits on the server.
#[test]
fn the_pause_form_sends_only_whole_minutes_from_1_to_1440() {
    assert_page_has_ids(&["pause-form", "pause-minutes"]);
    assert_page_has(&[
        "novalidate",
        "type=\"number\"",
        "min=\"1\"",
        "max=\"1440\"",
        "Number.isInteger(",
        "Enter 1 to 1440 minutes",
    ]);
}

#[test]
fn the_page_has_a_resume_button_that_the_paused_state_shows() {
    assert_page_has_ids(&["resume"]);
    assert_page_has(&["paused"]);
}

/// The notice is hidden until the status names a newer version, and every part of it is filled
/// as text.
#[test]
fn the_update_notice_is_hidden_until_a_newer_version_is_known() {
    assert!(PAGE.contains("<section id=\"update\" hidden>"));
    assert_page_has_ids(&[
        "version",
        "update-text",
        "update-notes",
        "update-how",
        "install-state",
        "install",
    ]);
    assert_page_has(&[" is available", "can_install"]);
}

#[test]
fn the_install_button_asks_before_it_posts() {
    let asks = PAGE
        .find("confirm(\"Update to v")
        .expect("the install button asks");
    let posts = PAGE.find("/api/update").expect("the install button posts");

    assert!(asks < posts);
}
