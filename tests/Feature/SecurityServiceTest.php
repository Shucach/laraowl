<?php

use App\Models\Project;
use App\Models\Record;
use App\Services\SecurityService;

function analyzeRequest(array $payload): Record
{
    $project = Project::factory()->create();
    $record = Record::factory()->create([
        'project_id' => $project->id,
        'payload' => array_merge(['t' => 'request', 'method' => 'GET', 'ip' => '203.0.113.7', 'status_code' => 200], $payload),
    ]);

    app(SecurityService::class)->analyze($project, $record);

    return $record->fresh();
}

test('ordinary links to php pages are not a remote file inclusion', function (array $payload) {
    expect(analyzeRequest($payload)->issue_id)->toBeNull();
})->with([
    'crawler user agent' => [[
        'url' => 'http://shop.test/',
        'headers' => json_encode(['user-agent' => ['facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)']], JSON_UNESCAPED_SLASHES),
    ]],
    'referer' => [[
        'url' => 'http://shop.test/catalog',
        'headers' => json_encode(['referer' => ['https://shop.test/ua/index.php']], JSON_UNESCAPED_SLASHES),
    ]],
    'requested page' => [[
        'url' => 'http://shop.test/ua/index.php',
    ]],
]);

test('a remote file url in a query parameter is a remote file inclusion', function () {
    $record = analyzeRequest(['url' => 'http://shop.test/index?page=http://evil.test/shell.txt']);

    expect($record->issue_id)->not->toBeNull()
        ->and($record->payload['_security_threats'])->toBe([[
            'type' => 'lfi_rfi',
            'source' => 'url_query',
            'pattern' => '/https?:\/\/.*\.(txt|php|exe)/i',
        ]]);
});

test('a value that only looks obfuscated is matched once', function () {
    $record = analyzeRequest(['url' => 'http://shop.test/assets/vendorbundlesmainchunk/.env']);

    expect($record->payload['_security_threats'])->toHaveCount(1)
        ->and($record->payload['_security_threats'][0]['source'])->toBe('url')
        ->and($record->payload['_security_score'])->toBe(50);
});

test('an obfuscated payload is decoded and matched', function () {
    $record = analyzeRequest([
        'url' => 'http://shop.test/search',
        'payload' => base64_encode('UNION SELECT password FROM users'),
    ]);

    expect($record->payload['_security_threats'])->toBe([[
        'type' => 'sqli',
        'source' => 'body_decoded',
        'pattern' => '/UNION\s+SELECT/i',
    ]])
        ->and($record->payload['_security_score'])->toBe(50);
});

test('a security tool user agent is detected', function (array|string $headers) {
    $record = analyzeRequest(['url' => 'http://shop.test/', 'headers' => $headers]);

    expect($record->payload['_security_threats'])->toBe([[
        'type' => 'anomaly',
        'detail' => 'Suspicious Security Tool Detected: sqlmap',
        'score' => 40,
    ]]);
})->with([
    'json string' => [json_encode(['user-agent' => ['sqlmap/1.8#stable (https://sqlmap.org)']], JSON_UNESCAPED_SLASHES)],
    'list of values' => [['user-agent' => ['sqlmap/1.8#stable (https://sqlmap.org)']]],
    'single value' => [['User-Agent' => 'sqlmap/1.8#stable (https://sqlmap.org)']],
]);
