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

package WeBWorK::Authen::LTIAdvantage::AccessTokenRequest;

=head1 NAME

WeBWorK::Authen::LTIAdvantage::AccessToken::

=cut


use strict;
use warnings;
use WeBWorK::Debug;
use WeBWorK::CGI;
use WeBWorK::Utils qw(grade_set grade_gateway grade_all_sets wwRound);
use HTTP::Request;
use LWP::UserAgent;
use HTML::Entities;
use Data::UUID;
use JSON;

use Digest::SHA qw(sha1_base64);
use Crypt::JWT qw(encode_jwt);

use WeBWorK::CourseEnvironment;
use WeBWorK::DB;
use WeBWorK::Debug;
use Data::Dumper;

# This package contains utilities for retrieving content membership from the LMS
sub new {
	my ($invocant, $ce, $deployment_id) = @_;
	my $class = ref($invocant) || $invocant;
	my $db = new WeBWorK::DB($ce->{dbLayout});
	my $self = {
		ce => $ce,
		db => $db,
		deployment_id => $deployment_id,
		error => '',
	};
	bless $self, $class;
	return $self;
}

sub getNamesAndRoleAccessToken {
	my $self = shift;

	my $request_result = $self->getAccessTokenForScope("https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly");
	if ($request_result) {
		return $request_result->{access_token};
	}
	return 0;
}

sub getAssignmentAndGradesLineItemAccessToken {
	my ($self, $scope) = @_;

	my $request_result = $self->getAccessTokenForScope("https://purl.imsglobal.org/spec/lti-ags/scope/lineitem");
	if ($request_result) {
		return $request_result->{access_token};
	}
	return 0;
}

sub getAssignmentAndGradesResultReadonlyAccessToken {
	my ($self, $scope) = @_;

	my $request_result = $self->getAccessTokenForScope("https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly");
	if ($request_result) {
		return $request_result->{access_token};
	}
	return 0;
}

sub getAssignmentAndGradesScoreAccessToken {
	my ($self, $scope) = @_;

	my $request_result = $self->getAccessTokenForScope("https://purl.imsglobal.org/spec/lti-ags/scope/score");
	if ($request_result) {
		return $request_result->{access_token};
	}
	return 0;
}

sub getAccessTokenForScope {
	my ($self, $scope) = @_;

	my $deployment_id = $self->{deployment_id};
	my $ce = $self->{ce};

	my $extralog = WebworkBridge::ExtraLog->new($ce);

	if (!defined($ce->{bridge}{lti_deployments}{$deployment_id}))
	{
		$self->{error} = "Unknown deployment_id '$deployment_id'. ";
		$extralog->logLTIRequest($self->{error});
		debug($self->{error});
		return 0;
	}

	my $access_token_url = $ce->{bridge}{lti_deployments}{$deployment_id}{oauth2_access_token_url};
	my $tool_client_id = $ce->{bridge}{lti_deployments}{$deployment_id}{tool_client_id};
	my $tool_private_key = $ce->{bridge}{lti_deployments}{$deployment_id}{tool_private_key};

	my $ug = new Data::UUID;
	my $uuid = $ug->create_str;
	$uuid =~ s/\-//g;

	my $time = time;
	my $data = {
		iss => $ce->{server_root_url},
		sub => $tool_client_id,
		aud => $access_token_url,
		iat => $time,
		exp => $time + 3600,
		jti => $uuid
	};

	my $jwt = encode_jwt(payload=>$data, alg=>'RS256', key=>\$tool_private_key, extra_headers=>{typ=>"JWT"});
	$extralog->logLTIRequest("Requesting LTI Access Token for scope: $scope for deployment: $deployment_id");
	debug("Requesting LTI Access Token for scope: $scope for deployment: $deployment_id");

	my $ua = LWP::UserAgent->new();
	my $response = $ua->post($access_token_url, {
		grant_type => encode_entities('client_credentials'),
		client_assertion_type => encode_entities('urn:ietf:params:oauth:client-assertion-type:jwt-bearer'),
		client_assertion => $jwt,
		scope => encode_entities($scope)
	});

	unless($response->is_success()) {
		$self->{error} = "LTI Access Token Request failed. ". $response->message . " \n" .$response->content;
		$extralog->logLTIRequest($self->{error});
		debug($self->{error});
		return 0;
	}

	my $request_result = from_json($response->content);
	unless(defined($request_result->{'access_token'})) {
		$self->{error} = "LTI Access Token Request failed. No Access Token given.";
		$extralog->logLTIRequest($self->{error});
		$extralog->logLTIRequest(Dumper($request_result));
		debug($self->{error});
		debug(Dumper($request_result));
		return 0;
	}

	$extralog->logLTIRequest("LTI Access Token request successful for deployment: $deployment_id with access token: ".$request_result->{'access_token'});
	debug("LTI Access Token request successful for deployment: $deployment_id with access token: ".$request_result->{'access_token'});

	return $request_result;
}

1;

