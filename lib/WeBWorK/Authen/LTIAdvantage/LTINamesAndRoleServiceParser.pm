package WeBWorK::Authen::LTIAdvantage::LTINamesAndRoleServiceParser;

use strict;
use warnings;

use XML::Simple;
use WeBWorK::Debug;
use Data::Dumper;

##### Exported Functions #####
sub new
{
	my ($class, $deployment_id, $ce, $data) = @_;

	my $self = {
		deployment_id => $deployment_id,
		ce => $ce,
		data => $data
	};
	bless $self, $class;
	return $self;
}

sub get_members {
	my $self = shift;

	my $data = $self->{data};

	my @members = ();

	for my $member (@{$data->{'members'}}) {
		# Each membership has a status of either Active or Inactive.
		# If the status is not specified then a status of Active must be assumed.
		if (defined($member->{"status"}) && $member->{"status"} eq "Inactive") {
			next;
		}
		my $user = $self->get_user_info($member);

		push(@members, $user);
	}

	return @members;
}

sub get_user_info {
	my ($self, $member) = @_;
	my $ce = $self->{ce};

	my $deployment_id = $self->{deployment_id};

	my $user = {};

	$user->{'loginid'} = $self->get_user_identifier($member);
	$user->{'deployment_id'} = $deployment_id;
	$user->{'lti_user_id'} = $member->{"user_id"};
	$user->{'firstname'} = $member->{"given_name"};
	$user->{'lastname'} = $member->{"family_name"};
	$user->{'email'} = $member->{"email"};

	# convert from internal perl UTF8 to binary UTF8, note that this means
	# I'm expecting these to go straight into the database, not be used in
	# any more perl ops
	utf8::encode($user->{'firstname'});
	utf8::encode($user->{'lastname'});

	# set user permissions
	$user->{'studentid'} = '';
	$user->{'permission'} = $self->get_permissions($member);
	if ($user->{'permission'} == $ce->{userRoles}{student}) {
		$user->{'studentid'} = $self->get_student_number($member);
	}

	return $user;
}

sub get_user_identifier {
	my ($self, $member) = @_;
	my $ce = $self->{ce};

	my $deployment_id = $self->{deployment_id};

	if (exists($ce->{bridge}{lti_deployments}{$deployment_id}{user_identifier_field})) {
		my $user_identifier_field = $ce->{bridge}{lti_deployments}{$deployment_id}{user_identifier_field};
		my @user_identifier_parts = split(/\|/, $user_identifier_field);

		for my $message (@{$member->{"message"}}) {
			unless ($message->{"https://purl.imsglobal.org/spec/lti/claim/message_type"} eq "basic-lti-launch-request") {
				next;
			}

			my $data_ref = $message;
			foreach my $user_identifier_part (@user_identifier_parts) {
				if (!defined($data_ref->{$user_identifier_part})) {
					return $member->{"user_id"};
				}
				$data_ref = $data_ref->{$user_identifier_part};
			}

			if (!defined($data_ref) || ref($data_ref) eq 'HASH' || ref($data_ref) eq 'ARRAY' || $data_ref eq '') {
				# fallback is to use lti_user_id (useful for LMS preview users)
				return $member->{"user_id"};
			}

			return $data_ref;
		}
	}

	# use user_id by default
	return $member->{"user_id"};
}

sub get_student_number {
	my ($self, $member) = @_;
	my $ce = $self->{ce};

	my $deployment_id = $self->{deployment_id};

	if (exists($ce->{bridge}{lti_deployments}{$deployment_id}{user_student_number_field})) {
		my $student_number_field = $ce->{bridge}{lti_deployments}{$deployment_id}{user_student_number_field};
		my @student_number_parts = split(/\|/, $student_number_field);


		for my $message (@{$member->{"message"}}) {
			unless ($message->{"https://purl.imsglobal.org/spec/lti/claim/message_type"} eq "basic-lti-launch-request") {
				next;
			}

			my $data_ref = $message;
			foreach my $student_number_part (@student_number_parts) {
				if (!defined($data_ref->{$student_number_part})) {
					return '';
				}
				$data_ref = $data_ref->{$student_number_part};
			}

			if (!defined($data_ref) || ref($data_ref) eq 'HASH' || ref($data_ref) eq 'ARRAY' || $data_ref eq '') {
				return '';
			}

			return $data_ref;
		}
	}

	# use '' by default
	return '';
}

# Core context roles
# http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator
# http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper
# http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor
# http://purl.imsglobal.org/vocab/lis/v2/membership#Learner
# http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor

# Instructor 	Sub-role
# Grader, GuestInstructor, Instructor, Lecturer, PrimaryInstructor
# SecondaryInstructor, TeachingAssistant, TeachingAssistantGroup
# TeachingAssistantOffering, TeachingAssistantSection, TeachingAssistantTemplate

sub get_permissions {
	my ($self, $member) = @_;
	my $ce = $self->{ce};

	my @roles = @{$member->{"roles"}};

	my $is_admin = 0;
	my $is_instructor = 0;
	my $is_content_developer = 0;
	my $is_ta = 0;
	my $is_student = 0;

	foreach my $role (@roles) {
		if ($role eq 'Administrator') {
			$is_admin = 1;
		} elsif ($role eq 'Instructor') {
			$is_instructor = 1;
		} elsif ($role eq 'ContentDeveloper') {
			$is_content_developer = 1;
		} elsif ($role eq 'TeachingAssistant') {
			$is_ta = 1;
		# TODO: remove || $role eq 'Student'
		} elsif ($role eq 'Learner' || $role eq 'Student') {
			$is_student = 1;
		}
	}

	if ($is_admin) {
		return $ce->{userRoles}{admin};
	} elsif ($is_instructor && !$is_ta) {
		return $ce->{userRoles}{professor};
	} elsif ($is_content_developer) {
		return $ce->{userRoles}{professor};
	} elsif ($is_ta) {
		return $ce->{userRoles}{ta};
	} elsif ($is_student) {
		return $ce->{userRoles}{student};
	} else {
		# default return guest or error??
		return $ce->{userRoles}{guest};
	}
}

1;

