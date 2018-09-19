###############################################################################
# WeBWorK Online Homework Delivery System
# Copyright � 2000-2016 The WeBWorK Project, http://openwebwork.sf.net/
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of either: (a) the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any later
# version, or (b) the "Artistic License" which comes with this package.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See either the GNU General Public License or the
# Artistic License for more details.
################################################################################

package WeBWorK::Authen::LTIAdvantage::NamesAndRoleService;

=head1 NAME

WeBWorK::Authen::LTIAdvantage::NamesAndRoleService::

=cut


use strict;
use warnings;
use WeBWorK::Debug;
use WeBWorK::CGI;
use WeBWorK::Utils qw(grade_set grade_gateway grade_all_sets wwRound);
use Net::OAuth;
use HTTP::Request;
use LWP::UserAgent;
use Digest::SHA qw(sha1_base64);
use JSON;

use WeBWorK::CourseEnvironment;
use WeBWorK::DB;
use WeBWorK::Debug;
use Data::Dumper;

use WeBWorK::Authen::LTIAdvantage::AccessTokenRequest;
use WebworkBridge::ExtraLog;
use WeBWorK::Authen::LTIAdvantage::LTINamesAndRoleServiceParser;

our $WW_DIRECTORY = $WebworkWebservice::WW_DIRECTORY;

# This package is used retrieving content membership from the LMS
sub new {
	my ($invocant, $ce, $db) = @_;
	my $class = ref($invocant) || $invocant;
	my $self = {
		ce => $ce,
		db => $db,
		error => '',
	};
	bless $self, $class;
	return $self;
}

sub getAllNamesAndRole {
	my $self = shift;
	my $ce = $self->{ce};
	my $db = $self->{db};

	my $extralog = WebworkBridge::ExtraLog->new($ce);
	my @lti_resource_links = $db->getAllLTIResourceLinks();

	# Step 1: make a request for each unique context (use first resource link id if multiple are present)
	my $deployments = {};
	my @membership_requests = ();
	foreach my $lti_resource_link (@lti_resource_links) {
		my $deployment_id = $lti_resource_link->deployment_id();
		my $context_id = $lti_resource_link->context_id();
		my $resource_link_id = $lti_resource_link->resource_link_id();
		my $context_memberships_url = $lti_resource_link->context_memberships_url();

		unless (exists($deployments->{$deployment_id})) {
			$deployments->{$deployment_id} = {};
		}

		unless (exists($deployments->{$deployment_id}{$context_id})) {
			$deployments->{$deployment_id}{$context_id} = 1;
			my $request = {
				'deployment_id' => $deployment_id,
				'resource_link_id' => $resource_link_id,
				'context_id' => $context_id,
				'context_memberships_url' => $context_memberships_url,
			};
			push(@membership_requests, $request);
		}
	}

	if (scalar(@membership_requests) == 0) {
		$self->{error} = "No valid Names and Roles requests.";
		$extralog->logLTIRequest($self->{error});
		return 0;
	}

	# Step 2: Fetch membership for each deployment for the context (merging results)

	# use a hash to prevent multiple instances of the same user
	my $users = {};
	foreach my $membership_request (@membership_requests) {
		my $members = $self->getNamesAndRole(
			$membership_request->{'deployment_id'},
			$membership_request->{'resource_link_id'},
			$membership_request->{'context_id'},
			$membership_request->{'context_memberships_url'},
		);

		# return error instead?
		next if (scalar(@{$members}) == 0);

		# merge memberships. If user exists in multiple places, use first result only
		foreach my $member (@{$members}) {
			# TODO: Allow updating lti_user table from multiple deployments (currently this part will only create/update the first one)
			unless(exists $users->{$member->{'loginid'}}) {
				$users->{$member->{'loginid'}} = $member;
			}
		}
	}
	my @return_value = values %{$users};

	return \@return_value;
}

sub getNamesAndRole {
	my ($self, $deployment_id, $context_id, $resource_link_id, $context_memberships_url) = @_;

	my $ce = $self->{ce};

	my $extralog = WebworkBridge::ExtraLog->new($ce);
	$extralog->logLTIRequest("Begining Names And Roles Service request for deployment: $deployment_id on context: $context_id with membership url: $context_memberships_url");

	if (!defined($ce->{bridge}{lti_deployments}{$deployment_id}) || !defined($ce->{bridge}{lti_deployments}{$deployment_id}{platform_public_key}))
	{
		$self->{error} = "Unknown deployment_id '$deployment_id'";
		$extralog->logLTIRequest($self->{error});
		return 0;
	}

	my $lti_access_token_request = WeBWorK::Authen::LTIAdvantage::AccessTokenRequest->new($ce, $deployment_id);
	my $access_token = $lti_access_token_request->getNamesAndRoleAccessToken();
	unless ($access_token) {
		$self->{error} = "Names And Roles Service request failed, unable to get an access token.";
		$extralog->logLTIRequest($self->{error});
		return 0;
	}

	my @users = ();
	my $request_url = $context_memberships_url;
	if ($resource_link_id) {
		if ($request_url =~ /\?/) {
			$request_url = $request_url."&rlid=".$resource_link_id
		} else {
			$request_url = $request_url."?rlid=".$resource_link_id
		}
	}
	while (1) {
		$extralog->logLTIRequest("Begining Names And Roles Service request for url: $request_url");
		debug("Begining Names And Roles Service request for url: $request_url");

		my $ua = LWP::UserAgent->new();
		$ua->default_header( 'Accept' => 'application/vnd.ims.lis.v2.membershipcontainer+json' );
		$ua->default_header( 'Authorization' => "Bearer $access_token");
		my $res = $ua->get($request_url);

		if ($res->is_success)
		{
			my $data = from_json($res->content);

			$extralog->logLTIRequest("Names And Roles Service request successful: \n" . Dumper($data) . "\n");
			# debug("Names And Roles Service request successful! \n" . Dumper($data). "\n");

			my $parser = WeBWorK::Authen::LTIAdvantage::LTINamesAndRoleServiceParser->new($deployment_id, $ce, $data);
			my @membership = $parser->get_members();

			if (scalar(@membership) == 0) {
				$self->{error} = "Names And Roles Service did not return any users.";
				$extralog->logLTIRequest($self->{error});
				return 0;
			}
			push(@users, @membership);

			if (defined($res->header("Link")) && $res->header("Link") =~ /rel=next/) {
				$request_url = $res->header("Link");
				# remove the :rel=next from the end
				$request_url =~ s/;rel=next//;
			} else {
				last;
			}
		} else {
			debug($res->status_line);
			$self->{error} = "Names And Roles Service request failed, unable to connect.";
			$extralog->logLTIRequest($self->{error});
			return 0;
		}
	}

	return \@users;
}

1;

