#include <Windows.h>
#include "misc_internal.h"
#include "inc\unistd.h"
#include "debug.h"

int posix_spawn_internal(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], HANDLE user_token, BOOLEAN prepend_module_path);

int
__posix_spawn_asuser(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], char* user)
{
	extern HANDLE password_auth_token;
	extern HANDLE sspi_auth_user;

	int r = -1;
	/* use token generated from password auth if already present */
	HANDLE user_token = NULL;
	
    BOOL is_user_system = FALSE;
    if (strcmp(user, "sshd")) {
      /*
       * Note, __posix_spawn_asuser() is called twice upon a session
       * establishment: on a 1st call the value of `user` is "sshd",
       * on a 2nd call the value of `user` is a name of a session user.
       */
      const PSID user_sid = get_sid(user);
      const PSID system_sid = get_sid("NT Authority\\System");
      is_user_system = IsValidSid(user_sid) && IsValidSid(system_sid) &&
        EqualSid(user_sid, system_sid);
      free(system_sid);
      free(user_sid);
    }

	if (password_auth_token)
		user_token = password_auth_token;
	else if (sspi_auth_user) 
		user_token = sspi_auth_user;

    /* No token is needed for the System account. */
	if (!is_user_system && !user_token && (user_token = get_user_token(user, 1)) == NULL) {
		error("unable to get security token for user %s", user);
		errno = EOTHER;
		return -1;
	}
	if (strcmp(user, "sshd"))
		load_user_profile(user_token, user);
	
	r = posix_spawn_internal(pidp, path, file_actions, attrp, argv, envp, user_token, TRUE);
	CloseHandle(user_token);
	return r;
}
