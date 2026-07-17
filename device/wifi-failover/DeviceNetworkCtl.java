package com.autorun.device;

import android.content.Context;
import android.net.TetheringManager;
import android.net.wifi.WifiManager;
import android.os.Looper;

import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class DeviceNetworkCtl {
    private static final int EXIT_USAGE = 2;
    private static final int EXIT_FAILED = 3;

    private DeviceNetworkCtl() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            System.exit(EXIT_USAGE);
        }

        Context context = getSystemContext();
        switch (args[0]) {
            case "wifi-connect":
                if (args.length != 2) {
                    usage();
                    System.exit(EXIT_USAGE);
                }
                connectSavedWifi(context, Integer.parseInt(args[1]));
                return;
            case "hotspot-start":
                startHotspot(context);
                return;
            default:
                usage();
                System.exit(EXIT_USAGE);
        }
    }

    private static Context getSystemContext() throws Exception {
        if (Looper.myLooper() == null) {
            Looper.prepareMainLooper();
        }
        Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
        Method systemMain = activityThreadClass.getDeclaredMethod("systemMain");
        Object activityThread = systemMain.invoke(null);
        Method getSystemContext = activityThreadClass.getDeclaredMethod("getSystemContext");
        return (Context) getSystemContext.invoke(activityThread);
    }

    private static void connectSavedWifi(Context context, int networkId) {
        WifiManager wifi = context.getSystemService(WifiManager.class);
        if (wifi == null) {
            fail("WifiManager unavailable");
        }

        boolean enabled = wifi.enableNetwork(networkId, true);
        boolean reconnecting = wifi.reconnect();
        System.out.println("wifi-connect networkId=" + networkId
                + " enabled=" + enabled + " reconnecting=" + reconnecting);
        if (!enabled && !reconnecting) {
            System.exit(EXIT_FAILED);
        }
    }

    private static void startHotspot(Context context) throws InterruptedException {
        TetheringManager tethering = context.getSystemService(TetheringManager.class);
        if (tethering == null) {
            fail("TetheringManager unavailable");
        }

        CountDownLatch completed = new CountDownLatch(1);
        AtomicInteger error = new AtomicInteger(Integer.MIN_VALUE);
        TetheringManager.TetheringRequest request =
                new TetheringManager.TetheringRequest.Builder(
                        TetheringManager.TETHERING_WIFI).build();

        tethering.startTethering(request, Runnable::run,
                new TetheringManager.StartTetheringCallback() {
                    @Override
                    public void onTetheringStarted() {
                        error.set(0);
                        completed.countDown();
                    }

                    @Override
                    public void onTetheringFailed(int errorCode) {
                        error.set(errorCode);
                        completed.countDown();
                    }
                });

        if (!completed.await(15, TimeUnit.SECONDS)) {
            fail("hotspot-start timed out");
        }
        if (error.get() != 0) {
            fail("hotspot-start error=" + error.get());
        }
        System.out.println("hotspot-start success");
    }

    private static void fail(String message) {
        System.err.println(message);
        System.exit(EXIT_FAILED);
    }

    private static void usage() {
        System.err.println("Usage: DeviceNetworkCtl wifi-connect <networkId> | hotspot-start");
    }
}
