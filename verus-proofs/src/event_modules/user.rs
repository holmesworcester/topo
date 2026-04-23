use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSignerKindCore {
    Missing,
    UserInvite,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSignerPlanCore {
    Ready,
    RejectMissingSigner,
    RejectWrongSignerType,
}

pub open spec fn decide_user_signer_plan_spec(
    signer: UserSignerKindCore,
) -> UserSignerPlanCore {
    match signer {
        UserSignerKindCore::Missing => UserSignerPlanCore::RejectMissingSigner,
        UserSignerKindCore::UserInvite => UserSignerPlanCore::Ready,
        UserSignerKindCore::Other => UserSignerPlanCore::RejectWrongSignerType,
    }
}

pub fn decide_user_signer_plan_core(
    signer: UserSignerKindCore,
) -> (out: UserSignerPlanCore)
    ensures out == decide_user_signer_plan_spec(signer),
{
    match signer {
        UserSignerKindCore::Missing => UserSignerPlanCore::RejectMissingSigner,
        UserSignerKindCore::UserInvite => UserSignerPlanCore::Ready,
        UserSignerKindCore::Other => UserSignerPlanCore::RejectWrongSignerType,
    }
}

pub proof fn user_ready_implies_user_invite(signer: UserSignerKindCore)
    ensures
        decide_user_signer_plan_spec(signer) == UserSignerPlanCore::Ready
            ==> signer == UserSignerKindCore::UserInvite,
{
}

}
