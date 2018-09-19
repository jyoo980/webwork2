package WebworkBridge::Bridges::LTIBridge;
use base qw(WebworkBridge::Bridge);

##### Library Imports #####
use strict;
use warnings;

use Net::OAuth;
use Net::OAuth::ConsumerRequest;
use HTTP::Request::Common;
use LWP::UserAgent;
use Data::Dumper;
use JSON;
use Digest::SHA qw(sha1_base64);;
use MIME::Base64;
use URI::Escape qw(uri_escape);
use CGI;

use WeBWorK::CourseEnvironment;
use WeBWorK::DB;
use WeBWorK::Debug;

use WebworkBridge::Importer::Error;
use WeBWorK::Authen::LTIAdvantage::LTILaunchParser;
use WebworkBridge::ExtraLog;

use WeBWorK::Authen::LTIAdvantage;
use WeBWorK::Authen::LTIAdvantage::NamesAndRoleService;
use WeBWorK::Authen::LTIAdvantage::AssignmentAndGradeService;

$WeBWorK::Debug::Enabled = 1;

# Constructor
sub new
{
	my ($class, $r) = @_;
	my $self = $class->SUPER::new($r);
	my $ce = $r->ce;
	$self->{parser} = WeBWorK::Authen::LTIAdvantage::LTILaunchParser->new($ce, $r->param("id_token"));
	bless $self, $class;
	return $self;
}

sub accept
{
	my $self = shift;
	my $r = $self->{r};

	if ($r->param("id_token")) {
		return 1;
	}

	return 0;
}

# In order to simplify, we use the Webwork root URL for all LTI actions,
# e.g.: http://137.82.12.77/webworkdev/
# Cases to handle:
# * The course does not yet exist
# ** If user is instructor, ask if want to create course
# ** If user is student, inform that course does not exist
# * The course exists
# ** SSO login

sub run
{
	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;
	$r->{db} = new WeBWorK::DB($ce->{dbLayout});
	my $db = $r->db;
	my $parser = $self->{parser};

	if ($parser->{error}) {
		debug("parser error: ". $parser->{error});
		my $error_message = CGI::h2("LTI Launch Failed");
		if ($parser->{error} =~ m/^JWT: exp claim check failed/) {
			$error_message .= CGI::div({class=>"ResultsWithError"}, CGI::pre("Your launch request has expired. Please click on the LTI link again.") );
		} else {
			$error_message .= CGI::p("Unfortunately, the LTI launch failed. This might be a temporary condition. If it persists, please mail an error report with the time that the error occured and the exact error message below:");
			$error_message .= CGI::div({class=>"ResultsWithError"}, CGI::pre($parser->{error}) );
		}
		return $error_message;
	}

	# check if user wants to go directly to an assignment
	my $hwset = $parser->get_claim_param("custom", "homework_set");
	if ($hwset)
	{
		# not perfect sanitization, but need something
		$hwset = $parser->sanitizeCourseName($hwset);
		$self->{homeworkSet} = $hwset;
	}
	my $qset = $parser->get_claim_param("custom", "quiz_set");
	if ($qset)
	{
		# not perfect sanitization, but need something
		$qset = $parser->sanitizeCourseName($qset);
		$self->{quizSet} = $qset;
	}

	my $deployment_id = $parser->get_claim("deployment_id");
	my $context_id = $parser->get_claim_param("context", "id");
	my $course_id = $parser->getCourseName();

	# LTI processing
	if ($deployment_id && $context_id && $course_id)
	{
		debug("LTI detected\n");

		# verify message
		my $ret = $self->_verifyMessage();
		if ($ret) {
			debug("_verifyMessage error: ". $ret);
			my $error_message = CGI::h2("LTI Launch Failed");
			$error_message .= CGI::p("Unfortunately, the LTI launch failed. This might be a temporary condition. If it persists, please mail an error report with the time that the error occured and the exact error message below:");
			$error_message .= CGI::div({class=>"ResultsWithError"}, CGI::pre($ret) );
			return $error_message;
		}

		# Check for course existence
		if($db->existsLTIContext($deployment_id, $context_id)) {
        	my $lti_context = $db->getLTIContext($deployment_id, $context_id);
			# over write course id with value stored in context table
			$course_id = $lti_context->course_id();
		}

		# setup tmp course ce and db
		my $tmpce = WeBWorK::CourseEnvironment->new({
			%WeBWorK::SeedCE,
			courseName => $course_id,
			apache_hostname => $ce->{apache_hostname},
			apache_port => $ce->{apache_port},
			apache_is_ssl => $ce->{apache_is_ssl},
			apache_root_url => $ce->{apache_root_url},
		});

		# set request ce and db to courseID
		$r->{ce} = $tmpce;
		$r->{db} = new WeBWorK::DB($r->ce->{dbLayout});

		# direct the student directly to a homework assignment or quiz if needed
		my $redir = $r->uri . $course_id;
		if ($self->getHomeworkSet()) {
			$redir .= "/" . $self->getHomeworkSet();
		} elsif ($self->getQuizSet()) {
			$redir .= "/quiz_mode/" . $self->getQuizSet();
		}

		if (-e $tmpce->{courseDirs}->{root}) {
			# course exists
			$self->_updateLaunchUser();

			$ret = $self->updateCourse();
			if ($ret) {
				debug("updateCourse error: ". $ret);
				my $error_message = CGI::h2("LTI Launch Failed");
				$error_message .= CGI::p("Unfortunately, the LTI launch failed. This might be a temporary condition. If it persists, please mail an error report with the time that the error occured and the exact error message below:");
				$error_message .= CGI::div({class=>"ResultsWithError"}, CGI::pre($ret) );
				return $error_message;
			}
		} else {
			# course does not exist
			debug("Course does not exist, try LTI import.");

			$ret = $self->createCourse();
			if ($ret) {
				debug("createCourse error: ". $ret);
				my $error_message = CGI::h2("LTI Launch Failed");
				$error_message .= CGI::p("Unfortunately, import failed. This might be a temporary condition. If it persists, please mail an error report with the time that the error occured and the exact error message below:");
				$error_message .= CGI::div({class=>"ResultsWithError"}, CGI::pre($ret) );
				return $error_message;
			}

			my $message = "The course was successfully imported into Webwork.";
			$redir .= "?status_message=".uri_escape(CGI::div({class=>"ResultsWithoutError"}, $message));
		}

		# ensure authentification module is used
		$self->{useAuthenModule} = 1;

		my $q = CGI->new();
		print $q->redirect($redir);
	}

	return 0;
}

sub getAuthenModule
{
	my $self = shift;
	my $r = $self->{r};
	return WeBWorK::Authen::class($r->ce, "lti");
}

sub createCourse
{
	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;
	my $db = $r->db;
	my $parser = $self->{parser};

	my $permissions = $parser->get_permissions();
	if ($permissions < $ce->{userRoles}{professor}) {
		return error("Please ask your instructor to import this course into Webworks first.", "#e011");
	}

	my $ret = $self->SUPER::createCourse($parser->getCourseName(), $parser->get_claim_param("context", "title"));
	if ($ret) {
		return error("Create course failed: $ret", "#e010");
	}

	# store LTI credentials for auto-update
	$self->_updateLTISettings();

	# add current user to the course
	$self->_updateLaunchUser();

	# try to update roster if names and role service enabled
	$self->_updateClassRoster();

	return 0;
}

sub updateCourse
{
	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;
	my $db = $r->db;
	my $parser = $self->{parser};

	# store LTI credentials for auto-update
	$self->_updateLTISettings();

	debug("Checking to see if we can update the course.");
	# check roles to see if we can run update
	if (!defined($parser->get_claim("roles"))) {
		return error("LTI launch missing roles, NOT updating course.", "#e025");
	}

	my @roles = @{$parser->get_claim("roles")};
	my $allowedUpdate = 0;
	foreach my $role (@roles) {
		foreach my $update_role ($ce->{bridge}{roles_can_update}) {
			if ($update_role eq $role) {
				debug("Role $role allowed to update course.");
				$allowedUpdate = 1;
				last;
			}
		}
		last if ($allowedUpdate);
	}

	if (!$allowedUpdate) {
		debug("User not allowed to update course.");
		return 0;
	}

	# try to update roster if names and role service enabled
	$self->_updateClassRoster();

	# try to push out grades back to the LMS
	if (defined($parser->get_claim_param("custom", "gradesync"))) {
		return $self->_updateClassGrades();
	}

	return 0;
}

sub _updateLTISettings()
{
	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;
	my $db = $r->db;
	my $parser = $self->{parser};

	my $deployment_id = $parser->get_claim("deployment_id");
	my $context_id = $parser->get_claim_param("context", "id");
	my $resource_link_id = $parser->get_claim_param("resource_link", "id");

	my $lti_context;
	my $exists = $db->existsLTIContext($deployment_id, $context_id);

	if($exists) {
        $lti_context = $db->getLTIContext($deployment_id, $context_id);
    } else {
        $lti_context = $db->newLTIContext(
			deployment_id => $deployment_id,
			context_id => $context_id,
			# only set course_title and automatic_updates are only set up new lti contexts
			course_id => $ce->{courseName},
			automatic_updates => 1
		);
	}

	if($exists) {
        $db->putLTIContext($lti_context);
    } else {
        $db->addLTIContext($lti_context);
	}

	# only if resource_link_id is present
	if ($resource_link_id) {
		my $lti_resource_link;
		$exists = $db->existsLTIResourceLink($deployment_id, $context_id, $resource_link_id);

		if($exists) {
			$lti_resource_link = $db->getLTIResourceLink($deployment_id, $context_id, $resource_link_id);
		} else {
			$lti_resource_link = $db->newLTIResourceLink(
				deployment_id => $deployment_id,
				context_id => $context_id,
				resource_link_id => $resource_link_id,
			);
		}

		if (($self->getHomeworkSet() || $self->getQuizSet())) {
			my $setId = $self->getHomeworkSet() ? $self->getHomeworkSet() : $self->getQuizSet();
			$lti_resource_link->set_id($setId);
		}
		else {
			$lti_resource_link->set_id("");
		}

		my $resource_link_id = $parser->get_claim_param("resource_link", "id");

		if ($parser->get_nrps_claim()) {
			$lti_resource_link->context_memberships_url($parser->get_nrps_claim_param("context_memberships_url"));
			$lti_resource_link->context_service_version($parser->get_nrps_claim_param("service_version"));
		} else {
			$lti_resource_link->context_memberships_url("");
			$lti_resource_link->context_service_version("");
		}

		if ($parser->get_ags_claim()) {
			$lti_resource_link->lineitems_url($parser->get_ags_claim_param("lineitems"));
			$lti_resource_link->lineitem_url($parser->get_ags_claim_param("lineitem"));
			$lti_resource_link->scope_lineitem($parser->has_ags_claim_scope("lineitem"));
			$lti_resource_link->scope_lineitem_read_only($parser->has_ags_claim_scope("lineitem.readonly"));
			$lti_resource_link->scope_result_readonly($parser->has_ags_claim_scope("result.readonly"));
			$lti_resource_link->scope_result_score($parser->has_ags_claim_scope("score"));
		} else {
			$lti_resource_link->lineitems_url("");
			$lti_resource_link->lineitem_url("");
			$lti_resource_link->scope_lineitem("");
			$lti_resource_link->scope_lineitem_read_only("");
			$lti_resource_link->scope_result_readonly("");
			$lti_resource_link->scope_result_score("");
		}

		if($exists) {
			$db->putLTIResourceLink($lti_resource_link);
		} else {
			$db->addLTIResourceLink($lti_resource_link);
		}
	}
}

# Automatically add new users to course or update existing user information on launch.
# assign users to all the available assignments.
sub _updateLaunchUser()
{
	debug("Manage LTI Launch user account.");

	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;
	my $db = $r->db;
	my $parser = $self->{parser};
	my $deployment_id = $parser->get_claim("deployment_id");

	debug("Parsing user information.");
	# parse user from launch request
	my %user = $parser->get_user_info();

	debug(Dumper(\%user));

	my $updater = WebworkBridge::Importer::CourseUpdater->new($ce, $db, '');
	# check if user exists
	if ($db->existsUser($user{'loginid'})) {
		debug("Attempt to update user & assign assignments.");
		my $oldUser = $db->getUser($user{'loginid'});
		my $oldPermission = $db->getPermissionLevel($user{'loginid'});
		$updater->updateUser($oldUser, \%user, $oldPermission);

		# assign all visible homeworks to students
		if ($oldPermission->permission() <= $ce->{userRoles}{student}) {
			$updater->assignAllVisibleSetsToUser($user{'loginid'}, $db);
		}
	} else {
		debug("Attempt to create user & assign assignments.");
		$updater->addUser(\%user);
	}

	debug("Done.");
}

# Automatically add new users to course or update existing user information on launch.
# assign users to all the available assignments.
sub _updateClassRoster()
{
	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;
	my $db = $r->db;
	my $parser = $self->{parser};

	debug("Update class roster if available.");

	# try to update course enrolment
	if ($parser->get_nrps_claim()) {
		my $names_and_roles_service = WeBWorK::Authen::LTIAdvantage::NamesAndRoleService->new($ce, $db);
		my $membership = $names_and_roles_service->getAllNamesAndRole();
		unless ($membership) {
			debug("There was an issue fetching the class roster. ".$names_and_roles_service->{error});
			return error("There was an issue fetching the class roster. ".$names_and_roles_service->{error}, "#e016");
		}
		my $ret = $self->SUPER::updateCourse($ce, $db, $membership);
		if ($ret) {
			return error("Update Class Roster failed: $ret", "#e010");
		}
	}

	debug("Done.");
}

sub _updateClassGrades()
{
	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;
	my $db = $r->db;
	my $parser = $self->{parser};

	debug("Update class assignment grades.");

	# try to update course enrolment
	if ($parser->get_ags_claim()) {
		my $assignment_and_grade_service = WeBWorK::Authen::LTIAdvantage::AssignmentAndGradeService->new($ce, $db);
		my $ret = $assignment_and_grade_service->pushAllAssignmentGrades();
		if ($ret) {
			debug("There was an issue fetching updating class grades. ".$assignment_and_grade_service->{error});
			return error("There was an issue fetching updating class grades. ".$assignment_and_grade_service->{error}, "#e017");
		}
	}

	debug("Done.");
}

sub _verifyMessage()
{
	my $self = shift;
	my $r = $self->{r};
	# verify that the message hasn't been tampered with
	my $ltiauthen = WeBWorK::Authen::LTIAdvantage->new($r);
	my $ret = $ltiauthen->authenticate();
	if (!$ret)
	{
		return error("Error: LTI message integrity could not be verified. Check if the LTI launch URL has a trailing slash.","#e015");
	}
	return 0;
}

1;
