<?php
// Clean content for the fictional practice. Idempotent: pages are matched by slug.

$pages = [
    'home' => ['Welcome to Brightline Dental', 'Gentle, modern dentistry for the whole family. Same-week appointments, evening hours on Thursdays, and a team that explains every step before we start.'],
    'services' => ['Our services', 'Check-ups and cleanings, fillings, crowns, whitening, clear aligners and emergency visits. We bill most insurance plans directly.'],
    'about' => ['About us', 'Dr. Lena Ortiz opened Brightline in 2011. Today four dentists and nine hygienists look after more than six thousand patients.'],
    'contact' => ['Contact', 'Call 555-0142 or write to hello@brightline-dental.example. 1200 Lake Street, Maple Grove.'],
];

foreach ($pages as $slug => [$title, $text]) {
    $existing = get_page_by_path($slug);
    $data = [
        'post_type' => 'page',
        'post_status' => 'publish',
        'post_name' => $slug,
        'post_title' => $title,
        'post_content' => "<!-- wp:paragraph -->\n<p>{$text}</p>\n<!-- /wp:paragraph -->",
    ];
    if ($existing) {
        $data['ID'] = $existing->ID;
    }
    wp_insert_post($data);
}

$home = get_page_by_path('home');
update_option('show_on_front', 'page');
update_option('page_on_front', $home->ID);

$posts = [
    'whitening-myths' => ['Five whitening myths', 'Whitening does not weaken enamel when it is done right. Here is what actually matters.'],
    'kids-first-visit' => ["Your child's first visit", 'Bring them by their first birthday. We keep it short, playful and free of surprises.'],
    'night-guards' => ['Do you need a night guard?', 'Morning headaches and worn edges are the usual signs of grinding at night.'],
    'insurance-2026' => ['Insurance changes for 2026', 'Most plans reset in January. Book your second cleaning of the year before December.'],
];

foreach ($posts as $slug => [$title, $text]) {
    if (get_page_by_path($slug, OBJECT, 'post')) {
        continue;
    }
    wp_insert_post([
        'post_type' => 'post',
        'post_status' => 'publish',
        'post_name' => $slug,
        'post_title' => $title,
        'post_content' => "<!-- wp:paragraph -->\n<p>{$text}</p>\n<!-- /wp:paragraph -->",
    ]);
}

echo "content ok\n";
