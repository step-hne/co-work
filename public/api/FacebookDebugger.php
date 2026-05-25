<?php

declare(strict_types=1);

include_once('../connection.config.php');

header('Content-Type: application/json; charset=utf-8');

function ajax_api(mysqli $link, string $accessToken, string $subDomain): array
{
	$rows = [];
	$counter = 1;

	$stmt = mysqli_prepare($link, 'SELECT domain FROM addondomain WHERE sub_domain = ? ORDER BY domain ASC');
	if (!$stmt) {
		return $rows;
	}

	mysqli_stmt_bind_param($stmt, 's', $subDomain);
	mysqli_stmt_execute($stmt);
	$result = mysqli_stmt_get_result($stmt);

	if ($result) {
		while ($row = mysqli_fetch_assoc($result)) {
			$checkDomain = (string) ($row['domain'] ?? '');
			$graph = 'https://graph.facebook.com/';
			$post = 'id=' . urlencode('http://' . $checkDomain) . '&scrape=true&access_token=' . $accessToken;

			$request = curl_init();
			curl_setopt($request, CURLOPT_URL, $graph);
			curl_setopt($request, CURLOPT_POST, 1);
			curl_setopt($request, CURLOPT_POSTFIELDS, $post);
			curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($request, CURLOPT_SSL_VERIFYHOST, 2);
			curl_setopt($request, CURLOPT_SSL_VERIFYPEER, true);
			curl_setopt($request, CURLOPT_HEADER, 0);
			curl_setopt($request, CURLOPT_CONNECTTIMEOUT, 5);

			$data = curl_exec($request);
			$response = is_string($data) ? json_decode($data) : null;

			if (is_object($response) && !empty($response->url)) {
				$info = $checkDomain . ' : Domain Aman!';
			} elseif (is_object($response) && isset($response->error->message) && $response->error->message === '(#368) The action attempted has been deemed abusive or is otherwise disallowed') {
				$info = $checkDomain . ' : Domain Fraud!';
			} elseif (is_object($response) && isset($response->error->message)) {
				$info = (string) $response->error->message;
			} else {
				$info = $checkDomain . ' : Unknown response';
			}

			$rows[] = [
				'id' => $counter++,
				'sub_domain' => $info,
				'domain' => $checkDomain,
			];
		}
	}

	mysqli_stmt_close($stmt);

	return $rows;
}

$accessToken = trim((string) ($_GET['access_token'] ?? ''));
$subDomain = strtoupper(trim((string) ($_GET['sub_domain'] ?? 'GLOBAL')));

if ($accessToken === '') {
	http_response_code(400);
	echo json_encode(['ok' => false, 'err' => 'missing access_token']);
	exit;
}

echo json_encode(ajax_api($link, $accessToken, $subDomain));
