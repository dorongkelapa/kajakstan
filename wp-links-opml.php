<?php
/**
 * Outputs the OPML XML format for getting the links defined in the link administration.
 *
 * @package WordPress
 */

require_once __DIR__ . '/wp-load.php';

header( 'Content-Type: text/xml; charset=' . get_option( 'blog_charset' ), true );

echo '<?xml version="1.0" encoding="' . get_option( 'blog_charset' ) . '"?' . '>';
?>
<opml version="1.0">
	<head>
		<title><?php echo esc_html( get_bloginfo( 'name', 'display' ) ); ?></title>
		<dateCreated><?php echo gmdate( 'D, d M Y H:i:s' ); ?> GMT</dateCreated>
	</head>
	<body>
		<?php
		$links = get_bookmarks();
		if ( ! empty( $links ) ) {
			foreach ( $links as $link ) {
				?>
				<outline text="<?php echo esc_attr( $link->link_name ); ?>"
					title="<?php echo esc_attr( $link->link_name ); ?>"
					type="link"
					xmlUrl="<?php echo esc_url( $link->link_rss ); ?>"
					htmlUrl="<?php echo esc_url( $link->link_url ); ?>" />
				<?php
			}
		}
		?>
	</body>
</opml>
