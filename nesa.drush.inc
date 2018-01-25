<?php
/**
 * @file
 * Drush commands for nesa project.
 */
// Constants for Drupal Security Advisories.
define('DRUPALSA_AC_NONE', 4);
define('DRUPALSA_AC_BASIC', 2);
define('DRUPALSA_AC_COMPLEX', 1);
define('DRUPALSA_A_NONE', 4);
define('DRUPALSA_A_USER', 2);
define('DRUPALSA_A_ADMIN', 1);
define('DRUPALSA_CI_ALL', 5);
define('DRUPALSA_CI_SOME', 3);
define('DRUPALSA_CI_NONE', 0);
define('DRUPALSA_II_ALL', 5);
define('DRUPALSA_II_SOME', 3);
define('DRUPALSA_II_NONE', 0);
define('DRUPALSA_E_EXPLOIT', 5);
define('DRUPALSA_E_PROOF', 3);
define('DRUPALSA_E_THEORETICAL', 1);
define('DRUPALSA_TD_ALL', 3);
define('DRUPALSA_TD_DEFAULT', 2);
define('DRUPALSA_TD_UNCOMMON', 1);
// Constants for NextEuropa Security Advisories.
define('NESA_AC_NONE', 5);
define('NESA_AC_BASIC', 3);
define('NESA_AC_COMPLEX', 2);
define('NESA_A_NONE', 5);
define('NESA_A_NE', 4);
define('NESA_A_USER', 3);
define('NESA_A_ADMIN', 2);
define('NESA_A_ID', 1);
define('NESA_A_NONE_V2', 10);
define('NESA_A_NE_V2', 7);
define('NESA_A_USER_V2', 6);
define('NESA_A_ADMIN_V2', 3);
define('NESA_A_ID_V2', 1);
define('NESA_CI_ALL', 4);
define('NESA_CI_SOME', 2);
define('NESA_CI_NONE', 0);
define('NESA_II_ALL', 5);
define('NESA_II_SOME', 3);
define('NESA_II_NONE', 0);
define('NESA_E_EXPLOIT', 5);
define('NESA_E_PROOF', 4);
define('NESA_E_THEORETICAL', 2);
define('NESA_TD_ALL', 5);
define('NESA_TD_DEFAULT', 3);
define('NESA_TD_UNCOMMON', 2);
define('NESA_PI_A', 5);
define('NESA_PI_SD', 4);
define('NESA_PI_SS', 3);
define('NESA_PI_N', 1);
define('NESA_PI_A_V2', 10);
define('NESA_PI_SD_V2', 5);
define('NESA_PI_SS_V2', 2);
define('NESA_PI_N_V2', 0);

/**
 * Implements hook_drush_command().
 */
function nesa_drush_command() {
  $items['evaluate-risk'] = array(
    'description' => 'Generate the NextEurope Security Advisory.',
    'aliases' => array('nesa-er'),
    'callback' => '_nesa_drush_command_evaluate_risk',
    'arguments' => array(
      'modulename' => 'Name of the contrib module.',
      'drupalsa' => "Original script of Drupal Security Advisory's risk.",
      'permission' => 'Name of the permission.',
      'subsites' => 'Name of the subsites.',
    ),
  );
  $items['nesa-shortcut'] = array(
    'description' => 'Shortcut for evaluate the needed action on NESA without all details.',
    'aliases' => array('nesa-sc'),
    'callback' => '_nesa_drush_command_shortcut',
    'arguments' => array(
      'modulename' => 'Name of the contrib module.',
      'drupalsa' => "Original script of Drupal Security Advisory's risk.",
      'subsites' => 'Name of the subsites.',
    ),
  );

  return $items;
}
/**
 * Callback for the evaluate-risk command.
 *
 * @param string $modulename
 *   Name of the module.
 *
 * @param string $drupalsa
 *   Original security risk
 *
 * @param string $defined_permission
 *   List of permissions.
 *
 * @param string $defined_subsites
 *   List of subsites.
 */
function _nesa_drush_command_evaluate_risk($modulename, $drupalsa, $defined_permission = '', $defined_subsites = '') {
  $results = array(
    'enabled' => 0,
    'results' => array(),
    'permissions' => array(),
    'versions' => array(),
  );
  $permission_level_for_sa = array();
  $platform_impact_level = array();
  $platform_impact_level['NESA_PI_A'] = TRUE;
  if (!empty($defined_subsites)) {
    foreach (explode(",", $defined_subsites) as $subsite_name) {
      _nesa_check_a_subsite($subsite_name, $modulename, $permission_level_for_sa, $platform_impact_level, $results, $defined_permission);
    }
  }
  else {
    $sites = _drush_sitealias_all_list();
    foreach ($sites as $subsite_name => $values) {
      if (!in_array($subsite_name, array('@self', '@none'))) {
        _nesa_check_a_subsite($subsite_name, $modulename, $permission_level_for_sa, $platform_impact_level, $results, $defined_permission);
      }
    }
  }

  _nesa_calculate_nesa($drupalsa, $permission_level_for_sa, $platform_impact_level);
  _nesa_evaluate_risk_report($results, $modulename);
}

/**
 * Callback for the nesa-shortcut command.
 *
 * @param string $modulename
 *   Name of the module.
 *
 * @param string $drupalsa
 *   Original security risk
 *
 * @param string $defined_subsites
 *   List of subsites.
 */
function _nesa_drush_command_shortcut($modulename, $drupalsa, $defined_subsites = '') {
  $results = array(
    'module' => array(
      'name' => $modulename,
      'status' => '',
      'provider' => '',
    ),
    'enabled' => 0,
    'versions' => array(),
  );
  $counter = 0;
  if (!empty($defined_subsites)) {
    foreach (explode(",", $defined_subsites) as $subsite_name) {
      _nesa_check_a_subsite_shortcut($subsite_name, $modulename, $results);
    }
  }
  else {
    $sites = _drush_sitealias_all_list();
    foreach ($sites as $subsite_name => $values) {
      if (!in_array($subsite_name, array('@self', '@none'))) {
        $counter++;
        _nesa_check_a_subsite_shortcut($subsite_name, $modulename, $results);
      }
    }
  }
  _nesa_calculate_nesa_shortcut($drupalsa, $results, $counter);
}

/**
 * Basic logic for collecting information about a subsite.
 *
 * @param string $name
 *   Name of the subsite.
 *
 * @param string $modulename
 *   Name of the module.
 *
 * @param array $permission_level_for_sa
 *   Flag collector for permission related information.
 *
 * @param array $platform_impact_level
 *   Flag collector for authentication related information.
 *
 * @param array $results
 *   All results by subsites.
 *
 * @param string $defined_permission
 *   List of permissions.
 */
function _nesa_check_a_subsite($name, $modulename, &$permission_level_for_sa, &$platform_impact_level, &$results, $defined_permission = '') {
  $pmi_result = drush_invoke_process($name, 'pmi', array($modulename), array(), FALSE);
  $results['results'][$name]['status'] = $pmi_result['object'][$modulename]['status'];
  if ($results['results'][$name]['status'] == 'enabled') {
    $results['enabled']++;
    $results['versions'][$pmi_result['object'][$modulename]['version']][] = $name;
    if (substr($pmi_result['object'][$modulename]['path'], 0, 8) === 'profiles') {
      $platform_impact_level['NESA_PI_SD'] = TRUE;
    }
    else {
      $platform_impact_level['NESA_PI_SS'] = TRUE;
    }
    if (!empty($pmi_result['object'][$modulename]['permissions'])) {
      if (!empty($defined_permission)) {
        $pmi_result['object'][$modulename]['permissions'] = explode(",", $defined_permission);
      }
      foreach ($pmi_result['object'][$modulename]['permissions'] as $permission) {
        $permissions_result = drush_invoke_process($name, 'sqlq', array('SELECT role.rid FROM role_permission join role on role_permission.rid = role.rid WHERE role_permission.permission="' . $permission . '"'), array(), FALSE);
        foreach (array_filter(explode("\n", $permissions_result['output'])) as $rid) {
          switch ($rid) {
            case 1:
              $results['results'][$name]['permissions'][$permission][$rid]['name'] = 'Anonymous';
              $results['results'][$name]['permissions'][$permission][$rid]['count_of_users'] = 'infinity';
              $results['permissions'][$pmi_result['object'][$modulename]['version']][$permission]['Anonymous']['number_of_users'] = 'Unlimited number of';
              $results['permissions'][$pmi_result['object'][$modulename]['version']][$permission]['Anonymous']['number_of_sites']++;
              $results['permissions'][$pmi_result['object'][$modulename]['version']][$permission]['Anonymous']['sites'][] = $name;
              $permission_level_for_sa['NESA_A_NONE'] = TRUE;
              break;

            case 2:
              $results['results'][$name]['permissions'][$permission][$rid]['name'] = 'Authenticated user';
              $number_of_users = drush_invoke_process($name, 'sqlq', array('SELECT count(uid) FROM users'), array(), FALSE);
              $results['results'][$name]['permissions'][$permission][$rid]['count_of_users'] = $number_of_users['output'];
              $results['permissions'][$pmi_result['object'][$modulename]['version']][$permission]['Authenticated user']['number_of_users'] += $number_of_users['output'];
              $results['permissions'][$pmi_result['object'][$modulename]['version']][$permission]['Authenticated user']['number_of_sites']++;
              $results['permissions'][$pmi_result['object'][$modulename]['version']][$permission]['Authenticated user']['sites'][] = $name;
              $pmi_ecas = drush_invoke_process($name, 'pmi', array('ecas'), array(), FALSE);
              if ($pmi_ecas['object'][$modulename]['status'] == 'enabled') {
                $permission_level_for_sa['NESA_A_NE'] = TRUE;
              }
              else {
                $permission_level_for_sa['NESA_A_U'] = TRUE;
              }

              break;

            default:
              $permissions_result = drush_invoke_process($name, 'sqlq', array('SELECT concat(name, "|", count(uid)) FROM users_roles JOIN role on role.rid=users_roles.rid WHERE role.rid=' . $rid . ' GROUP BY name'), array(), FALSE);
              if (array_filter(explode("|", $permissions_result['output']))[0] == '') {
                $results['results'][$name]['permissions'][$permission][$rid] = 'No users.';
                $permission_level_for_sa['NESA_A_ID'] = TRUE;
              }
              else {
                $results['results'][$name]['permissions'][$permission][$rid]['name'] = array_filter(explode("|", $permissions_result['output']))[0];
                $results['results'][$name]['permissions'][$permission][$rid]['count_of_users'] = array_filter(explode("|", $permissions_result['output']))[1];
                $results['permissions'][$pmi_result['object'][$modulename]['version']][$permission][array_filter(explode("|", $permissions_result['output']))[0]]['number_of_users'] += array_filter(explode("|", $permissions_result['output']))[1];
                $results['permissions'][$pmi_result['object'][$modulename]['version']][$permission][array_filter(explode("|", $permissions_result['output']))[0]]['number_of_sites']++;
                $permission_level_for_sa['NESA_A_ADMIN'] = TRUE;
              }
              break;

          }
        }
      }
    }
    else {
      $results['results'][$name]['permissions'] = $modulename . " does not have permissions.";
    }
  }
  elseif (in_array($results['results'][$name]['status'], array('disabled', 'not installed'))){
    $platform_impact_level['NESA_PI_A_NOT'] = FALSE;
  }
}

/**
 * Basic logic for collecting information about a subsite.
 *
 * @param string $name
 *   Name of the subsite.
 *
 * @param string $modulename
 *   Name of the module.
 *
 * @param array $permission_level_for_sa
 *   Flag collector for permission related information.
 *
 * @param array $platform_impact_level
 *   Flag collector for authentication related information.
 *
 * @param array $results
 *   All results by subsites.
 *
 * @param string $defined_permission
 *   List of permissions.
 */
function _nesa_check_a_subsite_shortcut($name, $modulename, &$results) {
  $status_result = drush_invoke_process($name, 'sqlq', array('SELECT concat(status, "||", info, "||", filename) FROM system WHERE name="' . $modulename . '"'), array(), FALSE);
  if (array_filter(explode("||", $status_result['output']))[0] == "1") {
    $results['module']['status'] = 'enabled';
    $results['enabled']++;
    $info = unserialize(array_filter(explode("||", $status_result['output']))[1]);
    $results['versions'][$info['version']]['count']++;
    $filename = explode('/', array_filter(explode("||", $status_result['output']))[2]);
    $results['module']['provider'][] = in_array('profiles', $filename) ? 'Platform' : 'Subsite';
  }
}

/**
 * Generates NextEuropa Security Advisory with the original one.
 *
 * @param string $drupalsa
 *   Original security risk string.
 *
 * @param array $permission_level_for_sa
 *   Flags about permission levels.
 *
 * @param array $platform_impact_level
 *   Flags about authentication levels.
 */
function _nesa_calculate_nesa($drupalsa, $permission_level_for_sa, $platform_impact_level) {
  $categories = explode("/", $drupalsa);
  $drupal_sa_value = 0;
  $ne_sa_value_v1 = 0;
  $ne_sa_value_v2_cat1 = 0;
  $ne_sa_value_v2_cat2 = 0;
  $ne_sa_values = array();
  foreach ($categories as $category) {
    $category = explode(":", $category);
    $drupal_sa_value += constant("DRUPALSA_" . $category[0] . "_" . strtoupper($category[1]));
    switch ($category[0]) {
      case 'AC':
      case 'CI':
      case 'II':
      case 'TD':
        $ne_sa_values[$category[0]] = $category[0] . ':' . $category[1];
        $ne_sa_value_v1 += constant("NESA_" . $category[0] . "_" . strtoupper($category[1]));
        $ne_sa_value_v2_cat2 += constant("NESA_" . $category[0] . "_" . strtoupper($category[1]));
        break;

      case 'E':
        switch ($category[1]) {
          case 'Exploit':
            $ne_sa_values[$category[0]] = 'E:' . $category[1];
            $ne_sa_value_v1 += constant("NESA_E_EXPLOIT");
            $ne_sa_value_v2_cat2 += constant("NESA_E_EXPLOIT");
            break;
          case 'Proof':
          case 'Theoretical':
            $ne_sa_values[$category[0]] = 'E:Proof';
            $ne_sa_value_v1 += constant("NESA_E_PROOF");
            $ne_sa_value_v2_cat2 += constant("NESA_E_PROOF");
            break;

        }
        break;

      case 'A':
        switch ($category[1]) {
          case 'None':
            $ne_sa_values[$category[0]] = 'A:' . $category[1];
            $ne_sa_value_v1 += constant("NESA_A_NONE");
            $ne_sa_value_v2_cat1 = constant("NESA_A_NONE_V2");
            break;

          case 'User':
            if (isset($permission_level_for_sa['NESA_A_NE'])) {
              $ne_sa_values[$category[0]] = 'A:Non-EcasUser';
              $ne_sa_value_v1 += constant("NESA_A_NE");
              $ne_sa_value_v2_cat1 = constant("NESA_A_NE_V2");
            }
            else {
              $ne_sa_values[$category[0]] = 'A:User';
              $ne_sa_value_v1 += constant("NESA_A_USER");
              $ne_sa_value_v2_cat1 = constant("NESA_A_USER_V2");
            }
            break;

          case 'Administrator':
            if (isset($permission_level_for_sa['NESA_A_ADMIN'])) {
              $ne_sa_values[$category[0]] = 'A:Administrator';
              $ne_sa_value_v1 += constant("NESA_A_ADMIN");
              $ne_sa_value_v2_cat1 = constant("NESA_A_ADMIN_V2");
            }
            else {
              $ne_sa_values[$category[0]] = 'A:UID1';
              $ne_sa_value_v1 += constant("NESA_A_ID");
              $ne_sa_value_v2_cat1 = constant("NESA_A_ID_V2");
            }
            break;

        }
        break;

    }
  }
  if ($platform_impact_level['NESA_PI_A'] == TRUE && !isset($platform_impact_level['NESA_PI_A_NOT'])) {
    $ne_sa_values['NESA_PI'] = 'PI:All';
    $ne_sa_value_v1 += constant("NESA_PI_A");
    $ne_sa_value_v2_cat1 *= constant("NESA_PI_A_V2");
  }
  elseif (isset($platform_impact_level['NESA_PI_SD'])) {
    $ne_sa_values['NESA_PI'] = 'PI:SubsiteDefined';
    $ne_sa_value_v1 += constant("NESA_PI_SD");
    $ne_sa_value_v2_cat1 *= constant("NESA_PI_SD_V2");
  }
  elseif (isset($platform_impact_level['NESA_PI_SS'])) {
    $ne_sa_values['NESA_PI'] = 'PI:SubsiteSpecific';
    $ne_sa_value_v1 += constant("NESA_PI_SS");
    $ne_sa_value_v2_cat1 *= constant("NESA_PI_SS_V2");
  }
  else {
    $ne_sa_values['NESA_PI'] = 'PI:None';
    $ne_sa_value_v1 += constant("NESA_PI_N");
    $ne_sa_value_v2_cat1 *= constant("NESA_PI_N_V2");
  }
  print 'DrupalSA value: ' . $drupal_sa_value . '/25' . "\n";
  print 'Security risk: ' . $drupalsa . "\n";
  print 'NextEuropaSA value (v1): ' . $ne_sa_value_v1 . '/34' . "\n";
  print "NextEuropaSA value (v2): \nCAT1: " . $ne_sa_value_v2_cat1 . '/100' . "\nCAT2: " . $ne_sa_value_v2_cat2 . "/24\n";
  print 'Security risk: ' . implode('/', $ne_sa_values) . "\n";
}

/**
 * Generates NextEuropa Security Advisory with the original one.
 *
 * @param string $drupalsa
 *   Original security risk string.
 */
function _nesa_calculate_nesa_shortcut($drupalsa, $results, $counter) {

  $categories = explode("/", $drupalsa);
  $drupal_sa_value = 0;
  $ne_sa_value_v2_cat1 = 0;
  $ne_sa_values = array();
  foreach ($categories as $category) {
    $category = explode(":", $category);
    $drupal_sa_value += constant("DRUPALSA_" . $category[0] . "_" . strtoupper($category[1]));
    if ($category[0] == 'A') {
      switch ($category[1]) {
        case 'None':
          $ne_sa_values[$category[0]] = 'Authentication:None';
          $ne_sa_value_v2_cat1 = constant("NESA_A_NONE_V2");
          break;

        case 'User':
          $ne_sa_values[$category[0]] = 'Authentication:Untrusted Role';
          $ne_sa_value_v2_cat1 = constant("NESA_A_NE_V2");
          break;

        case 'Admin':
          $ne_sa_values[$category[0]] = 'Authentication:Trusted Role';
          $ne_sa_value_v2_cat1 = constant("NESA_A_ADMIN_V2");
          break;

      }
    }
  }
  if ($results['enabled'] == 0) {
    $ne_sa_values['NESA_PI'] = 'PlatformImpact:None';
    $ne_sa_value_v2_cat1 *= constant("NESA_PI_N_V2");
  }
  if ($counter == $results['enabled']) {
    $ne_sa_values['NESA_PI'] = 'PlatformImpact:All';
    $ne_sa_value_v2_cat1 *= constant("NESA_PI_A_V2");
  }
  elseif (in_array('Platform', $results['module']['provider'])) {
    $ne_sa_values['NESA_PI'] = 'PlatformImpact:SubsiteDefined';
    $ne_sa_value_v2_cat1 *= constant("NESA_PI_SD_V2");
  }
  else {
    $ne_sa_values['NESA_PI'] = 'PlatformImpact:SubsiteSpecific';
    $ne_sa_value_v2_cat1 *= constant("NESA_PI_SS_V2");
  }
  print "Shortcut evaluation for NESA about " . $results['module']['name']. " module.\n";
  print 'DrupalSA value: ' . $drupal_sa_value . '/25' . "\n";
  print 'Security risk: ' . $drupalsa . "\n";
  print "NextEuropaSA value (v2): \nCategory1 gives the score of " . $ne_sa_value_v2_cat1 . '/100 with the following items:' . "\n";
  print implode('/', $ne_sa_values) . "\n" . ($ne_sa_value_v2_cat1 > 49 ? "Needs full evaluation." : "Lower then investigation is needed now.") . "\n";
}

/**
 * Generate the report for evaluation.
 *
 * @param array $results
 *   All data by subsites.
 *
 * @param string $modulename
 *   Name of the module.
 */
function _nesa_evaluate_risk_report($results, $modulename) {
  print "----------------------------\n";
  print "--- Report -----------------\n";
  print "----------------------------\n";
  print "Tested module: " . $modulename . "\n";
  $dorg_project = drupal_http_request("https://updates.drupal.org/release-history/" . $modulename . "/7.x");
  $xml = new SimpleXMLElement($dorg_project->data);
  $latest_stable_versions = array();
  $covered_major_versions = array();
  foreach ($xml->releases->release as $release) {
    if (!in_array($release->version_major, $covered_major_versions) && !isset($release->version_extra)) {
      //print_r($release->terms);
      if (isset($release->terms->term)) {
        foreach ($release->terms->term as $term) {
          if ($term->value == 'Security update') {
            print "Latest security release: " . $release->version . " (" . format_date($release->date) . ")\n";
            $covered_major_versions[] = (string)$release->version_major[0];
            $latest_stable_versions[] = array(
              'major' => (string)$release->version_major[0],
              'patch' => (string)$release->version_patch[0],
            );
          }
        }
      }
    }
  }


  print "----------------------------\n";
  print "Number of tested subsites: " . count($results['results']) . "\n";
  print "Number of subsites that has " . $modulename . " enabled: " . $results['enabled'] . "\n";
  print "----------------------------\n";
  if (count($results['versions'])) {
    print "Available versions on the sites (" . count($results['versions']) . " different):\n";
    foreach ($results['versions'] as $version => $sites) {
      print "  - " . count($sites) . " use " . $version . "\n";
      list($major, $patch) = explode('.', substr($version, 4));
      foreach ($latest_stable_versions as $lsv) {
        if ($lsv['major'] == $major && $lsv['patch'] > $patch) {
          print " (unsecure version)\n";
          print "    Following sites should be updated: \n";
          print "      " . implode(", ", $sites) . "\n";
        }
        elseif ($lsv['major'] == $major && $lsv['patch'] < $patch) {
          print " (covered version)\n";
        }
      }
    }
    print "----------------------------\n";
  }
  if (count($results['permissions'])) {
    print "Available permissions on the sites (" . count($results['permissions']) . " different versions):\n";
    foreach ($results['permissions'] as $version => $permissions) {
      foreach ($permissions as $permission => $roles) {
        foreach ($roles as $rolename => $data) {
          print "  - " . $data['number_of_users'] . " users of '" . $rolename . "' use " . $version . " defined '" . $permission . "' permission on " . $data['number_of_sites'] . " sites.\n";
          if (in_array($rolename, array('Anonymous', 'Authenticated user'))) {
            print "    Following sites: " . implode(", ", $data['sites']) . "\n";
          }
        }
      }
    }
    print "----------------------------\n";
  }

}