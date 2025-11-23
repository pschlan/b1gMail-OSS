<?php
/*
 * b1gMail
 * Copyright (c) 2021 Patrick Schlangen et al
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

include('../serverlib/admin.inc.php');

if(isset($_REQUEST['action']) && $_REQUEST['action']=='login')
{
	$username 	= $_POST['username'];
	$pw 		= $_POST['password'];

	if(trim($username) != '' && trim($pw) != '')
	{
		$res = $db->Query('SELECT `adminid`,`username`,`password`,`password_salt`,`last_try` FROM {pre}admins WHERE `username`=?',
			$username);
		if($res->RowCount() == 1)
		{
			$adminUserRow = $res->FetchArray(MYSQLI_ASSOC);
			$res->Free();

			if($adminUserRow['last_try'] > (time()-60*5))
			{
				$errorMsg = sprintf($lang_admin['dattempt2'], FormatDate($adminUserRow['last_try']+60*5));
			}
			else
			{
				if($adminUserRow['last_try'] > 10)
				{
					$adminUserRow['last_try'] = 0;
					$db->Query('UPDATE {pre}admins SET `last_try`=0 WHERE `adminid`=?', $adminUserRow['adminid']);
				}
				$md5saltlogin=0;
				if(md5($pw.$adminUserRow['password_salt']) === $adminUserRow['password']) { // Update old passwords
					$newPW = password_hash($pw, PASSWORD_DEFAULT);
					$db->Query('UPDATE {pre}admins SET `password`=?,`password_salt`=? WHERE `adminid`=?', 
						$newPW, '', $adminUserRow['adminid']); // try update
					$res = $db->Query('SELECT `adminid`,`username`,`password`,`password_salt`,`last_try` FROM {pre}admins WHERE `username`=?',
					$username); // check length
					$lengthrow = $res->FetchArray(MYSQLI_ASSOC);
					if($newPW != $lengthrow['password']) { // make rollback
						$db->Query('UPDATE {pre}admins SET `password`=?,`password_salt`=? WHERE `adminid`=?', 
						$adminUserRow['password'], $adminUserRow['password_salt'], $adminUserRow['adminid']);
						$md5saltlogin=1;
					}
					else {
						$adminUserRow['password'] = $newPW;
					}
				}
				if(password_verify($pw, $adminUserRow['password']) || $md5saltlogin==1)
				{
					$db->Query('UPDATE {pre}admins SET `last_try`=0 AND `adminid`=?', $adminUserRow['adminid']);

					// create session
					session_start();
					$sessionID = session_id();
					$_SESSION['bm_adminLoggedIn']	= true;
					$_SESSION['bm_adminID']			= $adminUserRow['adminid'];
					$_SESSION['bm_adminAuth']		= hash('sha512', $adminUserRow['password'].$_SERVER['HTTP_USER_AGENT']);
					$_SESSION['bm_sessionToken']	= SessionToken();
					$_SESSION['bm_timezone']		= isset($_REQUEST['timezone'])
														? (int)$_REQUEST['timezone']
														: date('Z');
					// Create session cookie lock
					$_SESSION['adminsessionSecret'] = GenerateRandomKey('sessionSecret');
					setcookie('bm_admin_sessionSecret_'.substr($sessionID, 0, 16), $_SESSION['adminsessionSecret'], 0, '/');
					$_COOKIE['bm_admin_sessionSecret_'.substr($sessionID, 0, 16)] = $_SESSION['adminsessionSecret'];

					// log
					PutLog(sprintf('Admin <%s> logged in from <%s>',
						$adminUserRow['username'],
						$_SERVER['REMOTE_ADDR']),
						PRIO_NOTE,
						__FILE__,
						__LINE__);

					// redirect
					$jump = 'welcome.php?';
					if(isset($_REQUEST['jump']) && strpos($_REQUEST['jump'], '://') === false)
					{
						$jump = trim($_REQUEST['jump']);
						if(substr($jump, -1) != '&')
							$jump .= '&';
					}
					header(sprintf('Location: %ssid=%s',
						$jump,
						session_id()));
					exit();
				}
				else
				{
					// log
					PutLog(sprintf('Admin login from <%s> as <%s> failed (invalid password)',
						$_SERVER['REMOTE_ADDR'],
						$adminUserRow['username']),
						PRIO_NOTE,
						__FILE__,
						__LINE__);

					if($adminUserRow['last_try']+1 > 4)
					{
						// log
						PutLog(sprintf('Admin login for <%s> locked until %s',
							$adminUserRow['last_try'],
							date('r', time()+60*5)),
							PRIO_WARNING,
							__FILE__,
							__LINE__);
						$last_try = time();
					}
					else
						$last_try = $adminUserRow['last_try']+1;
					$db->Query('UPDATE {pre}admins SET `last_try`=? WHERE `adminid`=?',
						$last_try,
						$adminUserRow['adminid']);
					$errorMsg = $lang_admin['loginerror'];
				}
			}
		}
		else
		{
			$errorMsg = $lang_admin['loginerror'];

			// log
			PutLog(sprintf('Admin login from <%s> as <%s> failed (invalid username)',
				$_SERVER['REMOTE_ADDR'],
				$username),
				PRIO_NOTE,
				__FILE__,
				__LINE__);
		}

		$tpl->assign('error', $errorMsg);
	}
}
else if(isset($_REQUEST['action']) && $_REQUEST['action']=='logout')
{
	RequestPrivileges(PRIVILEGES_ADMIN);
	$_SESSION = array();
	session_destroy();
	header('Location: index.php');
	exit();
}

if(isset($_REQUEST['jump']))
	$tpl->assign('jump', $_REQUEST['jump']);
$tpl->assign('timezone', date('Z'));
$tpl->display('login.tpl');
?>