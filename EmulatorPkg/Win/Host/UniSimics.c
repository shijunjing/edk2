/*
  code copied from simics-base\core\src\misc\simple-simics\simple-simics.c
*/
#include "UniSimics.h"

static void
print_attribute(attr_value_t val)
{
        if (SIM_attr_is_invalid(val)) {
                // be quiet

        } else if (SIM_attr_is_integer(val)) {
                printf("%lld", SIM_attr_integer(val));

        } else if (SIM_attr_is_string(val)) {
                printf("%s", SIM_attr_string(val));

        } else if (SIM_attr_is_object(val)) {
                printf("%s", SIM_object_name(SIM_attr_object(val)));

        } else if (SIM_attr_is_boolean(val)) {
                printf("%s", SIM_attr_boolean(val) ? "True" : "False");

        } else if (SIM_attr_is_floating(val)) {
                printf("%g", SIM_attr_floating(val));

        } else if (SIM_attr_is_nil(val)) {
                printf("NIL");

        } else if (SIM_attr_is_list(val)) {
                printf("[");
                int first = 1;
                for (unsigned i = 0; i < SIM_attr_list_size(val); i++) {
                        if (!first) printf(", ");
                        first = 0;
                        print_attribute(SIM_attr_list_item(val, i));
                }
                printf("]");

        } else if (SIM_attr_is_dict(val)) {
                printf("{");
                int first = 1;
                for (unsigned i = 0; i < SIM_attr_dict_size(val); i++) {
                        if (!first) printf(", ");
                        first = 0;
                        print_attribute(SIM_attr_dict_key(val, i));
                        printf(" : ");
                        print_attribute(SIM_attr_dict_value(val, i));
                }
                printf("}");

        } else if (SIM_attr_is_data(val)) {
                printf("<data attribute>");
        } else {
                printf("<unknown attribute>");
        }
}

void
InitSimics(int argc, char *argv[], char *envp[])
{

  // set a few parameters for demo purpose
  static init_arg_t init_args[] = {
          {"quiet",    true,  .u.enabled = false},
          {"project",  false, .u.string  = "."},
          {"gui-mode", false, .u.string  = "no-gui"},
          {"cpu-mode", false, .u.string  = "any"},
          {NULL,       false, .u.string  = NULL}
  };
      
  /* This must come very early, since both text output and memory
     allocation needs it. */
  //https://simics-download.pdx.intel.com/simics-6/docs/html/reference-manual-api/simulator-api-functions.html#SIM_init_environment
  SIM_init_environment(argv,
                       1,    /* let Simics handle signals */
                       1);   /* allow Simics to dump core */

  /* Initialize the simulator core */
  SIM_init_simulator2(init_args);


  char line[1024];

  printf("Write some commands:\n");

  while (fgets(line, 1024, stdin)) {
          sigjmp_buf here;

          /* restart here when longjumping out (fatal Simics error) */
          while (sigsetjmp(here, 1) != 0)
                  printf("Returning to main() after a longjump\n");

          /* Tell Simics where to jump to */
          SIM_set_frontend_context(&here);

          char *nl = strrchr(line, '\n');
          if (nl)
                  *nl = 0;

          attr_value_t ret = SIM_run_command(line);
          if (SIM_clear_exception()) {
                  printf("Got exception: %s\n", SIM_last_error());
          } else {
                  printf("Command return value: ");
                  print_attribute(ret);
                  SIM_attr_free(&ret);
                  printf("\n");
          }
          
          /* Handle background work */
          SIM_process_pending_work();
  }
  return;
}