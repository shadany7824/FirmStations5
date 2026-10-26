/* PS4 homebrew controller test (for the OpenOrbis toolchain; runs in orbemu).
 *
 * Prints a line whenever the buttons, sticks or triggers change. Hold Cross for the heavy
 * vibration motor and Square for the light one. Options quits.
 *
 * Build:  .\examples\ps4\build_ps4.ps1 -Source examples\ps4\pad_test -Name pad_test `
 *            -Libs "-lc -lkernel -lc++ -lScePad -lSceUserService"
 * Run:    python -m orbemu examples\ps4\pad_test\x64\Debug\pad_test.oelf --timeout 60
 */
#include <stdio.h>
#include <orbis/Pad.h>

int sceUserServiceInitialize(void *params);
int sceUserServiceGetInitialUser(int *userId);
int sceKernelUsleep(unsigned int microseconds);

static OrbisPadData data, last;

static int moved(int a, int b) {
    int d = a - b;
    return d > 8 || d < -8;
}

static void print_buttons(unsigned int b) {
    if (b & ORBIS_PAD_BUTTON_UP)       printf(" UP");
    if (b & ORBIS_PAD_BUTTON_DOWN)     printf(" DOWN");
    if (b & ORBIS_PAD_BUTTON_LEFT)     printf(" LEFT");
    if (b & ORBIS_PAD_BUTTON_RIGHT)    printf(" RIGHT");
    if (b & ORBIS_PAD_BUTTON_CROSS)    printf(" CROSS");
    if (b & ORBIS_PAD_BUTTON_CIRCLE)   printf(" CIRCLE");
    if (b & ORBIS_PAD_BUTTON_SQUARE)   printf(" SQUARE");
    if (b & ORBIS_PAD_BUTTON_TRIANGLE) printf(" TRIANGLE");
    if (b & ORBIS_PAD_BUTTON_L1)       printf(" L1");
    if (b & ORBIS_PAD_BUTTON_R1)       printf(" R1");
    if (b & ORBIS_PAD_BUTTON_L2)       printf(" L2");
    if (b & ORBIS_PAD_BUTTON_R2)       printf(" R2");
    if (b & ORBIS_PAD_BUTTON_L3)       printf(" L3");
    if (b & ORBIS_PAD_BUTTON_R3)       printf(" R3");
    if (b & ORBIS_PAD_BUTTON_OPTIONS)  printf(" OPTIONS");
}

int main(void) {
    int user = 0, state = -1;
    unsigned char last_large = 0, last_small = 0;

    sceUserServiceInitialize(NULL);
    sceUserServiceGetInitialUser(&user);
    scePadInit();
    int pad = scePadOpen(user, 0, 0, NULL);
    printf("pad_test: user %d, pad handle %d. Options quits.\n", user, pad);

    for (;;) {
        if (scePadReadState(pad, &data) != 0) {
            printf("pad_test: scePadReadState failed\n");
            break;
        }
        if (data.connected != state) {
            state = data.connected;
            printf("pad_test: controller %s\n", state ? "connected" : "not connected");
        }
        if (data.buttons != last.buttons
            || moved(data.leftStick.x, last.leftStick.x) || moved(data.leftStick.y, last.leftStick.y)
            || moved(data.rightStick.x, last.rightStick.x) || moved(data.rightStick.y, last.rightStick.y)
            || moved(data.analogButtons.l2, last.analogButtons.l2)
            || moved(data.analogButtons.r2, last.analogButtons.r2)) {
            printf("buttons=0x%05x", data.buttons);
            print_buttons(data.buttons);
            printf("  L(%d,%d) R(%d,%d) L2=%d R2=%d\n",
                   data.leftStick.x, data.leftStick.y, data.rightStick.x, data.rightStick.y,
                   data.analogButtons.l2, data.analogButtons.r2);
            last = data;
        }

        OrbisPadVibeParam vibe;
        vibe.lgMotor = (data.buttons & ORBIS_PAD_BUTTON_CROSS) ? 255 : 0;
        vibe.smMotor = (data.buttons & ORBIS_PAD_BUTTON_SQUARE) ? 255 : 0;
        if (vibe.lgMotor != last_large || vibe.smMotor != last_small) {
            scePadSetVibration(pad, &vibe);
            last_large = vibe.lgMotor;
            last_small = vibe.smMotor;
        }

        if (data.buttons & ORBIS_PAD_BUTTON_OPTIONS) {
            printf("pad_test: Options pressed, bye\n");
            break;
        }
        sceKernelUsleep(16000);
    }
    scePadSetVibration(pad, &(OrbisPadVibeParam){0, 0});
    scePadClose(pad);
    return 0;
}
