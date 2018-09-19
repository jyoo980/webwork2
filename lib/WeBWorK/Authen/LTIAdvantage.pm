################################################################################
# WeBWorK Online Homework Delivery System
# Copyright � 2000-2007 The WeBWorK Project, http://openwebwork.sf.net/
# $CVSHeader: webwork2/lib/WeBWorK/Authen/Moodle.pm,v 1.14 2007/02/14 19:08:46 gage Exp $
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

package WeBWorK::Authen::LTIAdvantage;
use base qw/WeBWorK::Authen/;

use strict;
use warnings;
use WeBWorK::Debug;
use Net::OAuth;
use JSON::Validator qw(validate_json);
use Crypt::JWT qw(decode_jwt);
use WeBWorK::Authen::LTIAdvantage::LTILaunchParser;
use File::Basename;
use Data::Dumper;

sub get_credentials {
	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;

	# don't allow guest login using LTI
	if ($r->param("login_practice_user")) {
		$self->{log_error} = "no guest logins are available";
		$self->{error} = "No guest logins are available. Please try again in a few minutes.";
		return 0;
	}

	debug(("-" x 80) . "\n");
	debug("Start LTI Single Sign On Authentication\n");
	debug("Checking for required LTI parameters\n");

	if (!defined($r->param("id_token"))) {
		$self->{log_error} = "Unable to find id_token param.";
		$self->{error} = "Unable to find id_token param.";
		return 0;
	}

	my $parser = WeBWorK::Authen::LTIAdvantage::LTILaunchParser->new($ce, $r->param("id_token"));
	if ($parser->{error}) {
		$self->{log_error} = "Could not parse LTI launch. Error: \n".$parser->{error};
		$self->{error} = "Could not parse LTI launch. Error: \n".$parser->{error};
		return 0;
	}

	my $deployment_id = $parser->get_claim("deployment_id");
	if (!defined($deployment_id)) {
		$self->{log_error} = "Unable to find deployment id.";
		$self->{error} = "Unable to find deployment id.";
		return 0;
	}

	my $message_type = $parser->get_claim("message_type");
	if (!defined($message_type) || $message_type ne 'LtiResourceLinkRequest') {
		$self->{log_error} = "Invalid or missing LTI message type.";
		$self->{error} = "Invalid or missing LTI message type.";
		return 0;
	}

	my $version = $parser->get_claim("version");

	my $dirname = dirname(__FILE__);
	my $schema = $dirname."/LTIAdvantage/schema/1.3.0/LtiResourceLinkRequest.json";
	if ($version ne "1.3.0") {
		# for future, load different schemas as needed
		# $schema = $dirname."/LTIAdvantage/schema/1.3.0/LtiResourceLinkRequest.json";
	}

	my @errors = validate_json($parser->{data}, $schema);
	debug(Dumper(@errors));
	debug(Dumper($parser->{data}));
	if (@errors) {
		$self->{log_error} = "JSON Validation Errors:\n" . join("\n", map { "* [" . $_->{'path'} . "] " . $_->{'message'} } @errors);
		$self->{error} = "JSON Validation Errors:<br>" . join("<br>", map { "* [" . $_->{'path'} . "] " . $_->{'message'} } @errors);
      	return 0;
	}

	if (!defined($ce->{bridge}{lti_deployments}{$deployment_id}) || !defined($ce->{bridge}{lti_deployments}{$deployment_id}{platform_public_key})) {
		$self->{log_error} = "Unable to find a public key that matches '$deployment_id'.";
		$self->{error} = "Unable to find a public key that matches '$deployment_id'.";
		return 0;
	}

	# verify user_id
	my $user_id = $parser->get_user_identifier();
	if (!$user_id) {
		$self->{log_error} = "Missing or incorrect JWT Token field: Undefined user identifier for ".$deployment_id;
		$self->{error} = "Missing or incorrect JWT Token field: Undefined user identifier for ".$deployment_id;
		return 0;
	}

	$self->{user_id} = $user_id;
    $self->{login_type} = "normal";
    $self->{credential_source} = "LTIAdvantage";

	return 1;
}

sub authenticate {
	my $self = shift;
	my $r = $self->{r};
	my $ce = $r->ce;

	debug("Starting OAuth verification\n");

	if (!defined($r->param("id_token"))) {
		$self->{log_error} = "Unable to find id_token param.";
		$self->{error} = "Unable to find id_token param.";
		return 0;
	}

	my $parser = WeBWorK::Authen::LTIAdvantage::LTILaunchParser->new($ce, $r->param("id_token"));
	if ($parser->{error}) {
		$self->{log_error} = "Could not parse LTI launch. Error: \n".$parser->{error};
		$self->{error} = "Could not parse LTI launch. Error: \n".$parser->{error};
		return 0;
	}

	my $deployment_id = $parser->get_claim("deployment_id");
	if (!defined($ce->{bridge}{lti_deployments}{$deployment_id}) || !defined($ce->{bridge}{lti_deployments}{$deployment_id}{platform_public_key})) {
		$self->{log_error} = "Unable to find a public key that matches '$deployment_id'.";
		$self->{error} = "Unable to find a public key that matches '$deployment_id'.";
		return 0;
	}

	if (!decode_jwt(token => $r->param("id_token"), key => \$ce->{bridge}{lti_deployments}{$deployment_id}{platform_public_key})) {
		$self->{log_error} = "Failed JWT verification";
		$self->{error} = "Failed JWT verification";
		return 0;
	}
	debug("LTI OAuth Verification Successful");
	debug(("-" x 80) . "\n");
	return 1;
}

1;
