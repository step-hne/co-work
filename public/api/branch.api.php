<?php
declare(strict_types=1);

include_once '../connection.config.php';
require_once dirname(__DIR__, 2) . '/Base64URL.php';

header('Content-Type: application/json; charset=UTF-8');

function jsonResponse(array $payload, int $statusCode = 200): never
{
    http_response_code($statusCode);
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function isAllowedHttpUrl(string $url): bool
{
    if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
        return false;
    }

    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

    return $scheme === 'http' || $scheme === 'https';
}

function extractShortUrlFromResponse(mixed $payload): ?string
{
    if (is_string($payload)) {
        $candidate = trim($payload);
        if (isAllowedHttpUrl($candidate)) {
            return $candidate;
        }

        return null;
    }

    if (!is_array($payload)) {
        return null;
    }

    $preferredKeys = array(
        'shorturl',
        'short_url',
        'shortUrl',
        'url',
        'short',
        'result',
        'data',
        'link',
    );

    foreach ($preferredKeys as $key) {
        if (array_key_exists($key, $payload)) {
            $found = extractShortUrlFromResponse($payload[$key]);
            if ($found !== null) {
                return $found;
            }
        }
    }

    foreach ($payload as $value) {
        $found = extractShortUrlFromResponse($value);
        if ($found !== null) {
            return $found;
        }
    }

    return null;
}

function requestTrackrShortUrl(string $longUrl, string $shortlinkDomain = ''): ?string
{
    if (!function_exists('curl_init')) {
        return null;
    }

    $apiKey = app_env('TRACKR_API_KEY', '');

    if ($shortlinkDomain !== '') {
        $endpoint = 'https://' . $shortlinkDomain . '/api/shorten';
    } else {
        $endpoint = app_env('TRACKR_ENDPOINT', '');
    }

    $requestUrl = $endpoint
        . '?key=' . rawurlencode($apiKey)
        . '&url=' . rawurlencode($longUrl);

    $ch = curl_init($requestUrl);
    if ($ch === false) {
        return null;
    }

    $postFields = http_build_query(
        array(
            'url' => $longUrl,
        ),
        '',
        '&',
        PHP_QUERY_RFC3986
    );

    curl_setopt_array(
        $ch,
        array(
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postFields,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER => array(
                'Accept: application/json, text/plain, */*',
                'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
            ),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        )
    );

    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);

    if ($response === false || $curlError !== '') {
        return null;
    }

    if ($httpCode < 200 || $httpCode > 299) {
        return null;
    }

    $raw = trim((string) $response);
    if ($raw === '') {
        return null;
    }

    try {
        $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        $shortUrl = extractShortUrlFromResponse($decoded);
        if ($shortUrl !== null && isAllowedHttpUrl($shortUrl)) {
            return $shortUrl;
        }
    } catch (Throwable $e) {
        // ignore JSON parse error; plain text fallback below
    }

    if (isAllowedHttpUrl($raw)) {
        return $raw;
    }

    return null;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    jsonResponse(
        array(
            array(
                'shorturl' => null,
                'error' => 'Method Not Allowed',
            ),
        ),
        405
    );
}

function randomName(): string
{
    $names = array(
        'ashley','jessica','emily','sarah','samantha','brittany','amanda','elizabeth','taylor','megan','stephanie','kayla','lauren','jennifer','rachel','hannah','nicole','amber','alexis','courtney','victoria','danielle','alyssa','rebecca','jasmine','katherine','melissa','alexandra','brianna','chelsea','michelle','morgan','kelsey','tiffany','kimberly','christina','madison','heather','shelby','anna','mary','maria','allison','sara','laura','andrea','olivia','erin','haley','abigail','kaitlyn','jordan','natalie','vanessa','kelly','brooke','erica','kristen','julia','crystal','amy','katelyn','marissa','lindsey','paige','cassandra','sydney','katie','caitlin','kathryn','emma','shannon','angela','gabrielle','jacqueline','jenna','jamie','mariah','alicia','briana','alexandria','destiny','miranda','monica','brittney','catherine','savannah','sierra','sabrina','breanna','whitney','caroline','molly','madeline','erika','grace','diana','leah','angelica','lindsay','christine','kaitlin','cynthia','meghan','cheyenne','mackenzie','margaret','veronica','melanie','bailey','kristin','bianca','lisa','holly','kristina','alexa','ariel','bethany','hailey','leslie','april','casey','brenda','kathleen','julie','patricia','autumn','karen','gabriela','brandi','ana','rachael','kendra','karina','dominique','valerie','desiree','kara','carly','claire','tara','adriana','kaylee','natasha','michaela','chloe','jocelyn','kylie','krystal','hayley','caitlyn','alison','nancy','sophia','daisy','rebekah','dana','jillian','cassidy','alejandra','raven','jade','angel','summer','audrey','gabriella','chelsey','sandra','ariana','katrina','claudia','monique','meagan','joanna','kirsten','faith','mikayla','brandy','kiara','makayla','mallory','krista','deanna','yesenia','ashlee','cindy','mercedes','alisha','gina','lydia','felicia','mckenzie','zoe','bridget','marisa','priscilla','karla','kassandra','denise','jasmin','tori','isabella','selena','diamond','evelyn','anne','amelia','cristina','allyson','tabitha','abby','ashleigh','lacey','jazmin','isabel','asia','candace','ciara','cierra','colleen','jaclyn','carolyn','hope','linda','naomi','ellen','mia','teresa','meredith','guadalupe','hanna','renee','nichole','kendall','jazmine','tamara','britney','justine','tessa','susan','tatiana','tiara','daniela','maya','adrianna','genesis','rosa','mayra','kelli','kasey','candice','clarissa','aubrey','arianna','nina','theresa','carrie','wendy','raquel','marina','carmen','katelynn','maggie','ruby','heidi','jenny','jessie','katlyn','angelina','carolina','jacquelyn','camille','gloria','virginia','kiana','jordyn','cecilia','ebony','alexus','cara','kelsie','alissa','janet','charlotte','ashlyn','esmeralda','miriam','elise','martha','hillary','tia','melinda','jada','marie','carla','barbara','esther','stacey','kate','natalia','sharon','carissa','toni','alana','pamela','ruth','valeria','robin','rose','cassie','shayla','lillian','paola','riley','arielle','celeste','helen','alondra','brenna','sasha','alexia','logan','janelle','savanna','ann','lily','tanya','stacy','elena','vivian','kyra','tiana','tina','nikki','adrienne','ashton','anastasia','dakota','madeleine','tyler','callie','kylee','serena','devin','chelsie','kellie','sadie','annie','eva','imani','mckenna','tierra','marisol','christian','frances','elisabeth','aimee','devon','kyla','deborah','liliana','nadia','sonia','deja','jane','kennedy','paula','shawna','brooklyn','sophie','kira','karissa','kierra','madelyn','kristine','peyton','regina','sylvia','skylar','aaliyah','melody','alice','brittani','kali','lorena','bria','nicolette','francesca','sofia','larissa','alaina','tracy','delaney','kari','brianne','cortney','macy','leticia','shayna','taryn','jeanette','robyn','joy','tania','chasity','mikaela','stefanie','shanice','sidney','tayler','juliana','kailey','makenzie','kaitlynn','bryanna','kristi','carol','randi','breana','tasha','india','irene','kayleigh','emilee','elisa','josephine','corinne','mariana','payton','alma','maribel','simone','clara','cristal','yvonne','johanna','katharine','kristy','alyson','isabelle','julianna','kaila','yvette','christy','ciera','kourtney','christa','harley','rachelle','meaghan','abbey','destinee','tanisha','elaine','michele','kenya','perla','precious','blanca','jaime','donna','marilyn','marlene','nora','haylee','josie','cheyanne','angelique','ericka','giselle','misty','noelle','lucy','carley','iris','lyndsey','tiffani','cameron','kelley','daniella','judith','maritza','talia','sandy','diane','shana','trisha','anita','kelsi','lori','carina','allie','chantel','charity','gianna','julianne','shania','avery','chanel','kaley','aliyah','luz','hunter','hilary','stephany','leanna','nia','mollie','bonnie','paris','yasmin','yolanda','margarita','yasmine','alexandrea','janae','janice','alanna','alysha','julissa','kaleigh','shaina','casandra','darian','iesha','ivy','jill','kiersten','moriah','sheila','dawn','norma','skyler','kiera','paulina','thalia','viviana','antoinette','genevieve','keisha','tatyana','lizbeth','roxanne','alisa','desirae','beatriz','kacie','maranda','emilie','bridgette','edith','kassidy','suzanne','susana','tianna','chandler','rochelle','ryan','hallie','lucia','aisha','cayla','tyra','laurel','dorothy','keri','antonia','eileen','rocio','eliza','kaylin','baylee','haleigh','karly','tonya','kaylie','kelsea','mckayla','kaylyn','breanne','gretchen','micaela','alina','lacy','fabiola','rosemary','annette','kathy','keely','justice','lena','sally','shaniqua','shakira','latoya','selina','shauna','ashlie','eleanor','mara','shirley','jacklyn','jodi','carlie','katelin','noemi','reagan','brittni','joyce','charlene','khadijah','shantel','dallas','katarina','heaven','jena','madalyn','araceli','fatima','kerri','blair','reyna','tess','angie','katy','leanne','tammy','darlene','maegan','celina','christie','shanna','clare','justina','nathalie','karlee','yadira','hailee','kristie','lexus','bailee','jalisa','rhiannon','abbie','georgia','kori','lea','mindy','shelbi','skye','alex','corina','katlin','sonya','beverly','mariela','regan','celia','dulce','juanita','kasandra','ella','lesley','stacie','connie','karli','savanah','ashlynn','sade','shea','cheryl','rylee','essence','kaela','kiley','tabatha','aurora','karlie','latasha','ali','anissa','gwendolyn','jennie','kacey','lauryn','brook','brandie','elaina','kala','kalyn','kianna','kirstin','octavia','aileen','alycia','jana','jesse','jessika','lizette','mandy','carli','demi','ellie','leigh','beth','joanne','lara','loren','ayanna','phoebe','silvia','bobbie','debra','halie','jami','janessa','jaimie','latisha','melina','rita','shelbie','ashly','devan','eden','jayme','breann','kaci','christen','kirstie','athena','fiona','jaqueline','jenifer','kailee','lucero','patrice','staci','alysia','christiana','corey','sheena','brielle','constance','arlene','ava','elyse','makenna','adrian','gillian','kerry','kortney','kristyn','elissa','janette','traci','cecelia','celine','elisha','joselyn','maureen','nadine','roxana','allyssa','cori','macey','maura','racheal','rikki','sarai','brittanie','dianna','graciela','iliana','jackie','maddison','rebeca','shyanne','trinity','betty','gladys','judy','keishla','stevie','dayna','kristal','nikita','alayna','cora','darby','lorraine','yessenia','ayana','mya','sage','sherry','tracey','britany','montana','belinda','chantal','giovanna','juliet','micah','myra','addison','aspen','ayla','helena','hollie','ingrid','krysta','lakeisha','infant','lacie','maricela','myranda','bobbi','carlee','nataly','destini','domonique','itzel','karley','shelly','christin','destiney','terri','beatrice','tricia','danica','kristian','trista','bryana','dalia','leeann','magdalena','mireya','berenice','estefania','hali','joann','juana','leann','melisa','alessandra','irma','kenia','terra','tiffanie','baby','damaris','jazmyn','rhonda','hazel','janie','martina','sarina','tiera','yasmeen','ivette','jolene','aja','alesha','billie','jerrica','joan','liana','marcella','nayeli','noel','olga','tyesha','catalina','kia','lynn','tatum','alysa','asha','audra','britni','janay','janine','kallie','kimberley','pauline','alecia','annika','kaycee','scarlett','vanesa','bernadette','devyn','elyssa','lourdes','marisela','chaya','daphne','emerald','joelle','kassie','katerina','katheryn','macie','monika','anabel','annmarie','breonna','eliana','elsa','halle','kathrine','kaylynn','lesly','maira','mariam','marlena','susanna','annamarie','betsy','jessenia','malia','princess','ashli','astrid','dina','dominque','eunice','griselda','sydnie','yaritza','china','francheska','jayla','jean','katlynn','kayli','layla','leandra','lynette','xiomara','yazmin','zoey','anika','ashanti','dara','darcy','debbie','eboni','isamar','lexi','miracle','whitley','abbigail','aleah','anais','carson','emilia','franchesca','laurie','liza','mariel','marlee','stormy','anjelica','chelsi','gabriel','haylie','kalie','lana','lexie','paloma','salina','doris','leila','lizeth','drew','jamila','kailyn','kayley','kelcie','lidia','sydnee','amani','ashely','aubree','deana','jessi','jodie','keila','kendal','kimberlee','reina','yajaira','alena','brea','georgina','joana','meranda','mikala','nikole'
    );

    return $names[random_int(0, count($names) - 1)];
}

function fetchRandomAddonDomain(mysqli $db, string $subDomain): ?string
{
    $rangeStmt = mysqli_prepare(
        $db,
        'SELECT MIN(id) AS min_id, MAX(id) AS max_id FROM addondomain WHERE sub_domain = ?'
    );
    if (!$rangeStmt instanceof mysqli_stmt) {
        return null;
    }

    mysqli_stmt_bind_param($rangeStmt, 's', $subDomain);
    mysqli_stmt_execute($rangeStmt);
    $rangeResult = mysqli_stmt_get_result($rangeStmt);
    $range = $rangeResult instanceof mysqli_result ? mysqli_fetch_assoc($rangeResult) : null;
    if ($rangeResult instanceof mysqli_result) {
        mysqli_free_result($rangeResult);
    }
    mysqli_stmt_close($rangeStmt);

    if (!is_array($range) || $range['min_id'] === null || $range['max_id'] === null) {
        return null;
    }

    $minId = (int) $range['min_id'];
    $maxId = (int) $range['max_id'];
    if ($minId < 1 || $maxId < $minId) {
        return null;
    }

    $randomId = random_int($minId, $maxId);
    $domain = fetchAddonDomainAtOrAfterId($db, $subDomain, $randomId);

    return $domain ?? fetchAddonDomainAtOrAfterId($db, $subDomain, $minId);
}

function fetchAddonDomainAtOrAfterId(mysqli $db, string $subDomain, int $minimumId): ?string
{
    $stmt = mysqli_prepare(
        $db,
        'SELECT domain FROM addondomain WHERE sub_domain = ? AND id >= ? ORDER BY id ASC LIMIT 1'
    );
    if (!$stmt instanceof mysqli_stmt) {
        return null;
    }

    mysqli_stmt_bind_param($stmt, 'si', $subDomain, $minimumId);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = $result instanceof mysqli_result ? mysqli_fetch_assoc($result) : null;
    if ($result instanceof mysqli_result) {
        mysqli_free_result($result);
    }
    mysqli_stmt_close($stmt);

    if (!is_array($row) || empty($row['domain']) || !is_string($row['domain'])) {
        return null;
    }

    return $row['domain'];
}

try {
    $url = (string) ($_POST['longurl'] ?? '');
    $id = (string) ($_POST['id'] ?? '');
    $subId = (string) ($_POST['sub_id'] ?? '');
    $pickurl = (string) ($_POST['pickurl'] ?? '');
    $canonicalUrl = (string) ($_POST['longurl'] ?? '');
    $userLp = (string) ($_POST['user_lp'] ?? '');
    $fbtext = (string) ($_POST['fbtext'] ?? '');
    $fbimg = (string) ($_POST['fbimg'] ?? '');
    $lg = (string) ($_POST['lg'] ?? '');

    if ($url === '') {
        jsonResponse(
            array(
                array(
                    'shorturl' => null,
                    'error' => 'Missing longurl',
                ),
            ),
            400
        );
    }

    if ($fbtext === '') {
        $t = "Hi! I'm: " . ucwords(randomName()) . " - On live shows!";
    } else {
        $t = $fbtext;
    }

    $genurl = $url;

    if ($url === 'https://{sub}.global/{click_id}') {
        $domain = fetchRandomAddonDomain($link, 'global');
        if ($domain !== null) {
            $genurl = 'https://{sub}.' . $domain . '/{click_id}';
        }
    } elseif ($url === 'https://{sub}.u_rand/{click_id}') {
        $domain = fetchRandomAddonDomain($link, $subId);
        if ($domain !== null) {
            $genurl = 'https://{sub}.' . $domain . '/{click_id}';
        }
    }

    $sp = randomName() . randomName();
    $strParam = array('{sub}', '{click_id}');
    $strBuild = array(
        $sp,
        base64url_encode(
            substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 5)
            . ',' . strtoupper($subId)
            . ',' . time()
            . ',' . $canonicalUrl
            . ',' . $userLp
            . ',' . $t
            . ',' . $fbimg
            . ',' . $lg
        ),
    );

    $urlEx = str_replace($strParam, $strBuild, htmlspecialchars_decode($genurl, ENT_QUOTES));

    if (!isAllowedHttpUrl($urlEx)) {
        jsonResponse(
            array(
                array(
                    'shorturl' => null,
                    'error' => 'Generated URL is invalid',
                ),
            ),
            400
        );
    }

    /*
     * Legacy compatibility:
     * $id dan $pickurl tetap diterima agar caller lama tidak pecah,
     * tetapi Branch sudah dihapus total.
     */
    unset($id, $pickurl);

    // Shortener runs on the same full host as the generated URL
    $generatedHost = (string) parse_url($urlEx, PHP_URL_HOST);
    $_short = requestTrackrShortUrl($urlEx, $generatedHost);
    if ($_short === null) {
        $_short = $urlEx;
    }

    jsonResponse(
        array(
            array(
                'shorturl' => $_short,
            ),
        )
    );
} catch (Throwable $e) {
    jsonResponse(
        array(
            array(
                'shorturl' => null,
                'error' => 'Internal Server Error',
            ),
        ),
        500
    );
}
