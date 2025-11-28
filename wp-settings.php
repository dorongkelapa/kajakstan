<?php
/**
 * Used to set up and fix common variables and include
 * the WordPress procedural and class library.
 *
 * @package WordPress
 */

// Stop if ABSPATH is not set.
if ( ! defined( 'ABSPATH' ) ) {
	die( 'No direct access.' );
}

// Load most of WordPress.
require ABSPATH . WPINC . '/load.php';
require ABSPATH . WPINC . '/default-constants.php';

wp_initial_constants();
wp_check_php_mysql_versions();

require ABSPATH . WPINC . '/compat.php';
require ABSPATH . WPINC . '/functions.php';
require ABSPATH . WPINC . '/class-wp-fatal-error-handler.php';
require ABSPATH . WPINC . '/wp-db.php';
require ABSPATH . WPINC . '/plugin.php';
require ABSPATH . WPINC . '/pomo/mo.php';
require ABSPATH . WPINC . '/l10n.php';
require ABSPATH . WPINC . '/class-wp-locale.php';

$GLOBALS['wp_locale'] = new WP_Locale();

require ABSPATH . WPINC . '/class-wp-walker.php';
require ABSPATH . WPINC . '/class-wp-hash.php';
require ABSPATH . WPINC . '/class-wp-roles.php';

$GLOBALS['wp_roles'] = new WP_Roles();

require ABSPATH . WPINC . '/class-wp-user.php';
require ABSPATH . WPINC . '/class-wp-query.php';
require ABSPATH . WPINC . '/class-wp-theme.php';
require ABSPATH . WPINC . '/class-wp-widget-factory.php';

$GLOBALS['wp_widget_factory'] = new WP_Widget_Factory();

require ABSPATH . WPINC . '/general-template.php';
require ABSPATH . WPINC . '/link-template.php';
require ABSPATH . WPINC . '/script-loader.php';
require ABSPATH . WPINC . '/taxonomy.php';
require ABSPATH . WPINC . '/rewrite.php';

$GLOBALS['wp_rewrite'] = new WP_Rewrite();

require ABSPATH . WPINC . '/class-wp.php';

$GLOBALS['wp'] = new WP();

require ABSPATH . WPINC . '/class-wp-theme.php';
require ABSPATH . WPINC . '/template.php';
require ABSPATH . WPINC . '/post.php';
require ABSPATH . WPINC . '/class-wp-post-type.php';
require ABSPATH . WPINC . '/class-wp-tax-query.php';

do_action( 'plugins_loaded' );

wp_set_internal_encoding();

require ABSPATH . WPINC . '/option.php';
require ABSPATH . WPINC . '/class-wp-user-query.php';

wp_plugin_directory_constants();
wp_cookie_constants();

require ABSPATH . WPINC . '/class-wp-taxonomy.php';

$GLOBALS['wp_taxonomies'] = array();

require ABSPATH . WPINC . '/meta.php';

wp_register_default_headers();

do_action( 'init' );

$reserved = wp_get_sites();
do_action( 'setup_theme' );

require ABSPATH . WPINC . '/theme.php';

do_action( 'after_setup_theme' );

require ABSPATH . WPINC . '/user.php';
require ABSPATH . WPINC . '/session.php';

do_action( 'init' );
do_action( 'widgets_init' );

if ( ! isset( $GLOBALS['wp_the_query'] ) ) {
	$GLOBALS['wp_the_query'] = new WP_Query();
}
$GLOBALS['wp_query'] = $GLOBALS['wp_the_query'];

require ABSPATH . WPINC . '/shortcodes.php';
require ABSPATH . WPINC . '/embed.php';

do_action( 'wp_loaded' );
