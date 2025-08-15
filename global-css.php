<?php
/**
 * Plugin Name: Global CSS
 * Description: Safely add site-wide CSS from the dashboard. Includes CodeMirror editor, admin-apply toggle, safe-mode, caching, and one-click reset.
 * Version:     1.1.0
 * Author:      Candace Crowe Design / John Gottshalk
 * Text Domain: ccd-global-css
 * License:     GPLv2 or later
 */

namespace CCD\GlobalCSS;

if (!defined('ABSPATH')) {
    exit;
}

final class Plugin {
    const OPT_CSS         = 'ccd_global_css_code';
    const OPT_APPLY_ADMIN = 'ccd_global_css_apply_admin';
    const TRANSIENT_KEY   = 'ccd_global_css_rendered_style';
    const NONCE_FIELD     = 'ccd_global_css_nonce';
    const NONCE_ACTION    = 'ccd_global_css_save';
    const NONCE_RESET     = 'ccd_global_css_reset';
    const SAFE_QUERY_ARG  = 'ccd_global_css_safe';
    const MAX_LEN         = 200000; // ~200 KB limit to avoid runaway options

    private static ?self $instance = null;

    public static function instance(): self {
        return self::$instance ??= new self();
    }

    private function __construct() {
        // Settings API
        add_action('admin_init', [$this, 'register_settings']);

        // Admin UI
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);

        // Print CSS (front-end + optionally admin)
        add_action('wp_head', [$this, 'print_css'], 999);
        add_action('admin_head', [$this, 'print_css_in_admin'], 999);

        // Handle reset
        add_action('admin_post_ccd_global_css_reset', [$this, 'handle_reset']);

        // Clear cache when options change
        add_action('update_option_' . self::OPT_CSS, [$this, 'bust_cache'], 10, 3);
        add_action('update_option_' . self::OPT_APPLY_ADMIN, [$this, 'bust_cache'], 10, 3);
        add_action('add_option_'    . self::OPT_CSS, [$this, 'bust_cache'], 10, 2);
        add_action('add_option_'    . self::OPT_APPLY_ADMIN, [$this, 'bust_cache'], 10, 2);
        add_action('delete_option_' . self::OPT_CSS, [$this, 'bust_cache'], 10, 1);
        add_action('delete_option_' . self::OPT_APPLY_ADMIN, [$this, 'bust_cache'], 10, 1);

        // Uninstall cleanup (registered only when this file is loaded)
        register_uninstall_hook(__FILE__, [__CLASS__, 'uninstall']);
    }

    public function register_settings(): void {
        // CSS option
        register_setting(
            'ccd_global_css_group',
            self::OPT_CSS,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_css'],
                'default'           => '',
            ]
        );

        // Apply in admin option
        register_setting(
            'ccd_global_css_group',
            self::OPT_APPLY_ADMIN,
            [
                'type'              => 'boolean',
                'sanitize_callback' => fn($v) => (bool)$v,
                'default'           => false,
            ]
        );

        // Section + fields (kept minimal)
        add_settings_section(
            'ccd_global_css_section',
            __('Global CSS', 'ccd-global-css'),
            function () {
                echo '<p>' . esc_html__(
                    'Add CSS that loads site-wide. If you lock yourself out with bad admin CSS, visit any admin page with “?ccd_global_css_safe=1” to temporarily disable it and use the Reset button below.',
                    'ccd-global-css'
                ) . '</p>';
            },
            'ccd_global_css_page'
        );

        add_settings_field(
            self::OPT_CSS,
            __('Custom CSS', 'ccd-global-css'),
            [$this, 'render_css_field'],
            'ccd_global_css_page',
            'ccd_global_css_section'
        );

        add_settings_field(
            self::OPT_APPLY_ADMIN,
            __('Also apply in wp-admin', 'ccd-global-css'),
            [$this, 'render_apply_admin_field'],
            'ccd_global_css_page',
            'ccd_global_css_section'
        );
    }

    public function admin_menu(): void {
        add_theme_page(
            __('Global CSS', 'ccd-global-css'),
            __('Global CSS', 'ccd-global-css'),
            'manage_options',
            'ccd-global-css',
            [$this, 'render_page']
        );
    }

    public function enqueue_admin_assets($hook): void {
        if ($hook !== 'appearance_page_ccd-global-css') {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        // Code editor (CodeMirror)
        $settings = wp_enqueue_code_editor([
            'type'         => 'text/css',
            'codemirror'   => [
                'indentUnit' => 2,
                'tabSize'    => 2,
                'lineNumbers'=> true,
                'styleActiveLine' => true,
                'matchBrackets'   => true,
            ],
            'csslint'      => [
                // Relax some rules to reduce false positives for custom admin CSS
                'errors'   => true,
                'box-model'=> false,
                'ids'      => false,
                'adjoining-classes' => false,
            ],
        ]);

        if ($settings) {
            wp_add_inline_script(
                'code-editor',
                'window.ccdGlobalCssEditorSettings = ' . wp_json_encode($settings) . ';'
            );
        }

        wp_enqueue_script('wp-theme-plugin-editor'); // ensures code-editor deps
        wp_enqueue_style('wp-codemirror');           // editor styling
    }

    public function render_page(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'ccd-global-css'));
        }

        $css         = get_option(self::OPT_CSS, '');
        $apply_admin = (bool) get_option(self::OPT_APPLY_ADMIN, false);

        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Global CSS', 'ccd-global-css'); ?></h1>

            <?php if (isset($_GET['reset']) && $_GET['reset'] === 'success'): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Global CSS has been reset.', 'ccd-global-css'); ?></p></div>
            <?php endif; ?>

            <?php if (isset($_GET['safe']) && $_GET['safe'] === '1'): ?>
                <div class="notice notice-warning is-dismissible"><p><?php echo esc_html__('Safe mode is active (admin CSS temporarily disabled).', 'ccd-global-css'); ?></p></div>
            <?php endif; ?>

            <form method="post" action="options.php">
                <?php
                settings_fields('ccd_global_css_group');
                do_settings_sections('ccd_global_css_page');
                ?>

                <textarea id="ccd-global-css-textarea" name="<?php echo esc_attr(self::OPT_CSS); ?>" rows="20" style="width:100%;font-family:Menlo,Consolas,monospace;"><?php echo esc_textarea($css); ?></textarea>

                <p>
                    <label>
                        <input type="checkbox" name="<?php echo esc_attr(self::OPT_APPLY_ADMIN); ?>" value="1" <?php checked($apply_admin, true); ?> />
                        <?php echo esc_html__('Also load this CSS in wp-admin (use with caution).', 'ccd-global-css'); ?>
                    </label>
                </p>

                <?php submit_button(__('Save CSS', 'ccd-global-css')); ?>
            </form>

            <hr />

            <h2><?php echo esc_html__('Safety', 'ccd-global-css'); ?></h2>
            <p>
                <?php
                echo wp_kses_post(
                    sprintf(
                        /* translators: %s is a code example of the query string */
                        __('If wp-admin becomes unreadable, add %s to any admin URL to temporarily disable admin CSS.', 'ccd-global-css'),
                        '<code>?'. self::SAFE_QUERY_ARG .'=1</code>'
                    )
                );
                ?>
            </p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" onsubmit="return confirm('<?php echo esc_js(__('Reset all Global CSS? This cannot be undone.', 'ccd-global-css')); ?>');">
                <input type="hidden" name="action" value="ccd_global_css_reset" />
                <?php wp_nonce_field(self::NONCE_RESET); ?>
                <?php submit_button(__('Reset Global CSS', 'ccd-global-css'), 'delete'); ?>
            </form>
        </div>

        <script>
        (function(){
            // Initialize CodeMirror on the textarea if available.
            if ( window.wp && wp.codeEditor && window.ccdGlobalCssEditorSettings ) {
                wp.codeEditor.initialize( 'ccd-global-css-textarea', window.ccdGlobalCssEditorSettings );
            }
        }());
        </script>
        <?php
    }

    public function render_css_field(): void {
        // Rendered inline in render_page() so CodeMirror can hook it easily.
        echo '<p class="description">' . esc_html__('Enter raw CSS only. HTML and JS will be stripped.', 'ccd-global-css') . '</p>';
    }

    public function render_apply_admin_field(): void {
        // Rendered inline in render_page() for a single cohesive form.
        echo '';
    }

    public function print_css(): void {
        if ($this->is_safe_mode()) {
            // Safe mode never disables front-end CSS; only admin CSS is suppressed.
            // So do nothing special here.
        }

        $style = $this->get_cached_style();
        if ($style) {
            echo $style; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        }
    }

    public function print_css_in_admin(): void {
        if ($this->is_safe_mode()) {
            // Admin CSS suppressed in safe mode
            return;
        }

        $apply_admin = (bool) get_option(self::OPT_APPLY_ADMIN, false);
        if (!$apply_admin) {
            return;
        }

        $style = $this->get_cached_style();
        if ($style) {
            echo $style; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        }
    }

    private function is_safe_mode(): bool {
        // Safe-mode only affects admin to help recover.
        return is_admin() && isset($_GET[self::SAFE_QUERY_ARG]) && $_GET[self::SAFE_QUERY_ARG] === '1';
    }

    private function get_cached_style(): string {
        $cached = get_transient(self::TRANSIENT_KEY);
        if (is_string($cached)) {
            return $cached;
        }
        $css = (string) get_option(self::OPT_CSS, '');
        $css = trim($css);
        if ($css === '') {
            return '';
        }
        $sanitized = $this->sanitize_css($css, true); // second arg hints “from output”
        if ($sanitized === '') {
            return '';
        }
        $style = "<style id=\"ccd-global-css\">\n{$sanitized}\n</style>";
        // Cache for 12 hours; bust on option change/update
        set_transient(self::TRANSIENT_KEY, $style, 12 * HOUR_IN_SECONDS);
        return $style;
    }

    public function bust_cache(): void {
        delete_transient(self::TRANSIENT_KEY);
    }

    /**
     * Sanitize CSS input.
     * - Strip tags (no HTML/JS).
     * - Remove @import with external URLs.
     * - Enforce max length.
     * - Normalize line endings + trim.
     */
    public function sanitize_css($raw, bool $from_output = false): string {
        if (!current_user_can('manage_options')) {
            return '';
        }

        $css = (string) $raw;

        // Enforce max length to avoid giant options
        if (strlen($css) > self::MAX_LEN) {
            $css = substr($css, 0, self::MAX_LEN);
        }

        // Remove all HTML tags
        $css = wp_strip_all_tags($css, true);

        // Normalize line endings
        $css = str_replace(["\r\n", "\r"], "\n", $css);
        $css = trim($css);

        if ($css === '') {
            return '';
        }

        // Block external @import and @charset (security + consistency)
        // Remove @import url(...) where ... starts with http/https or //
        $css = preg_replace('#@import\s+url\(\s*[\'"]?(?:https?:)?//#i', '/* blocked-import */', $css);
        $css = preg_replace('#@import\s+(?:https?:)?//#i', '/* blocked-import */', $css);
        // Remove @charset rules (must be first token in a CSS file; not meaningful here)
        $css = preg_replace('#@charset\s+["\'][^"\']*["\'];?#i', '/* removed-charset */', $css);

        // Optional: very light rule to drop stray <script> if it slipped past strip_all_tags somehow
        $css = preg_replace('#</?script[^>]*>#i', '', $css);

        // If sanitizing for output, a final trim
        if ($from_output) {
            $css = trim($css);
        }

        return $css;
    }

    public function handle_reset(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Insufficient permissions.', 'ccd-global-css'));
        }
        check_admin_referer(self::NONCE_RESET);
        delete_option(self::OPT_CSS);
        delete_option(self::OPT_APPLY_ADMIN);
        $this->bust_cache();
        wp_safe_redirect(add_query_arg(['page' => 'ccd-global-css', 'reset' => 'success'], admin_url('themes.php')));
        exit;
    }

    public static function uninstall(): void {
        delete_option(self::OPT_CSS);
        delete_option(self::OPT_APPLY_ADMIN);
        delete_transient(self::TRANSIENT_KEY);
    }
}

// Bootstrap
Plugin::instance();
