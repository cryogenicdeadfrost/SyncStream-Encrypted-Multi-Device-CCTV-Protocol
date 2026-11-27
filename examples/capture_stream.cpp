#include <syncstream/syncstream.hpp>

#include <cstdint>
#include <iostream>
#include <stdexcept>

#if defined(SYNCSTREAM_HAS_OPENCV)
#include <opencv2/opencv.hpp>
#endif

int main() {
#if !defined(SYNCSTREAM_HAS_OPENCV)
    std::cerr
        << "Capture example was built without OpenCV.\n"
        << "Reconfigure with -DSYNCSTREAM_BUILD_CAPTURE_EXAMPLE=ON and install OpenCV.\n";
    return 2;
#else
    try {
        const auto key = syncstream::mint_key();
        syncstream::CameraClient phone(key);
        syncstream::CameraServer camera(key);

        cv::VideoCapture capture(0);
        if (!capture.isOpened()) {
            throw std::runtime_error("could not open camera device 0");
        }

        std::cout << "Camera opened. Sending SyncStream start_recording command.\n";

        const auto start_wire = phone.make_command(
            "local-opencv-camera",
            syncstream::Cmd::start_recording);

        const auto start_request = camera.open_wire(start_wire);
        const auto start_reply = camera.make_response(start_request, true);
        const auto start_result = phone.open_response(start_reply);

        if (!start_result.accepted) {
            throw std::runtime_error("camera rejected start_recording");
        }

        cv::Mat frame;
        int frames = 0;
        while (frames < 100) {
            if (!capture.read(frame) || frame.empty()) {
                throw std::runtime_error("camera frame capture failed");
            }

            std::cout << "captured frame " << ++frames
                      << " (" << frame.cols << "x" << frame.rows << ")\n";
        }

        const auto stop_wire = phone.make_command(
            "local-opencv-camera",
            syncstream::Cmd::stop_recording);

        const auto stop_request = camera.open_wire(stop_wire);
        const auto stop_reply = camera.make_response(stop_request, true);
        const auto stop_result = phone.open_response(stop_reply);

        if (!stop_result.accepted) {
            throw std::runtime_error("camera rejected stop_recording");
        }

        capture.release();
        std::cout << "Capture example complete. 100 frames captured.\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Capture example failed: " << ex.what() << '\n';
        return 1;
    }
#endif
}
