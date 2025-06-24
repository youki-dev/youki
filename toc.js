// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="youki.html">Youki</a></li><li class="chapter-item expanded affix "><li class="spacer"></li><li class="chapter-item expanded "><a href="user/introduction.html"><strong aria-hidden="true">1.</strong> User Documentation</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="user/basic_setup.html"><strong aria-hidden="true">1.1.</strong> Basic Setup</a></li><li class="chapter-item expanded "><a href="user/basic_usage.html"><strong aria-hidden="true">1.2.</strong> Basic Usage</a></li><li class="chapter-item expanded "><a href="user/crates.html"><strong aria-hidden="true">1.3.</strong> Crates provided</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="user/libcgroups.html"><strong aria-hidden="true">1.3.1.</strong> libcgroups</a></li><li class="chapter-item expanded "><a href="user/libcontainer.html"><strong aria-hidden="true">1.3.2.</strong> libcontainer</a></li><li class="chapter-item expanded "><a href="user/liboci_cli.html"><strong aria-hidden="true">1.3.3.</strong> liboci-cli</a></li><li class="chapter-item expanded "><a href="user/libseccomp.html"><strong aria-hidden="true">1.3.4.</strong> libseccomp</a></li></ol></li><li class="chapter-item expanded "><a href="user/webassembly.html"><strong aria-hidden="true">1.4.</strong> Webassembly</a></li></ol></li><li class="chapter-item expanded "><li class="spacer"></li><li class="chapter-item expanded "><a href="community/introduction.html"><strong aria-hidden="true">2.</strong> Community</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="community/maintainer.html"><strong aria-hidden="true">2.1.</strong> Maintainer</a></li><li class="chapter-item expanded "><a href="community/governance.html"><strong aria-hidden="true">2.2.</strong> Governance</a></li><li class="chapter-item expanded "><a href="community/contributing.html"><strong aria-hidden="true">2.3.</strong> Contributing</a></li><li class="chapter-item expanded "><a href="community/chat.html"><strong aria-hidden="true">2.4.</strong> Chat</a></li></ol></li><li class="chapter-item expanded "><li class="spacer"></li><li class="chapter-item expanded "><a href="developer/introduction.html"><strong aria-hidden="true">3.</strong> Developer Documentation</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="developer/basics.html"><strong aria-hidden="true">3.1.</strong> Basics</a></li><li class="chapter-item expanded "><a href="developer/unwritten_rules.html"><strong aria-hidden="true">3.2.</strong> Unwritten Rules</a></li><li class="chapter-item expanded "><a href="developer/good_places_to_start.html"><strong aria-hidden="true">3.3.</strong> Good places to start</a></li><li class="chapter-item expanded "><a href="developer/documentation_mdbook.html"><strong aria-hidden="true">3.4.</strong> This Documentation</a></li><li class="chapter-item expanded "><a href="developer/repo_structure.html"><strong aria-hidden="true">3.5.</strong> Repository Structure</a></li><li class="chapter-item expanded "><a href="developer/debugging.html"><strong aria-hidden="true">3.6.</strong> Debugging</a></li><li class="chapter-item expanded "><a href="developer/crate_specific_information.html"><strong aria-hidden="true">3.7.</strong> Crate Specific Information</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="developer/libcgroups.html"><strong aria-hidden="true">3.7.1.</strong> libcgroups</a></li><li class="chapter-item expanded "><a href="developer/libcontainer.html"><strong aria-hidden="true">3.7.2.</strong> libcontainer</a></li><li class="chapter-item expanded "><a href="developer/liboci_cli.html"><strong aria-hidden="true">3.7.3.</strong> liboci-cli</a></li><li class="chapter-item expanded "><a href="developer/libseccomp.html"><strong aria-hidden="true">3.7.4.</strong> libseccomp</a></li><li class="chapter-item expanded "><a href="developer/youki.html"><strong aria-hidden="true">3.7.5.</strong> youki</a></li></ol></li><li class="chapter-item expanded "><a href="developer/e2e/e2e_tests.html"><strong aria-hidden="true">3.8.</strong> e2e tests</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="developer/e2e/rust_oci_test.html"><strong aria-hidden="true">3.8.1.</strong> rust oci tests</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="developer/e2e/integration_test.html"><strong aria-hidden="true">3.8.1.1.</strong> integration_test</a></li><li class="chapter-item expanded "><a href="developer/e2e/test_framework.html"><strong aria-hidden="true">3.8.1.2.</strong> test_framework</a></li><li class="chapter-item expanded "><a href="developer/e2e/runtimetest.html"><strong aria-hidden="true">3.8.1.3.</strong> runtimetest</a></li></ol></li><li class="chapter-item expanded "><a href="developer/e2e/containerd_integration_test_using_youki.html"><strong aria-hidden="true">3.8.2.</strong> containerd integration test</a></li><li class="chapter-item expanded "><a href="developer/e2e/runtime_tools.html"><strong aria-hidden="true">3.8.3.</strong> runtime tools</a></li></ol></li></ol></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
