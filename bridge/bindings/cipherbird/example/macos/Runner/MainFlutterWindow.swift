import AVFoundation
import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)
    LiveCamera.register(with: flutterViewController.registrar(forPlugin: "LiveCamera"))

    super.awakeFromNib()
  }
}

/// Camera frames for the live entropy playground: the luma plane of every
/// frame is sent over an event channel, nothing is recorded or stored.
final class LiveCamera: NSObject, FlutterStreamHandler,
  AVCaptureVideoDataOutputSampleBufferDelegate
{
  private let session = AVCaptureSession()
  private let queue = DispatchQueue(label: "dev.cipherbird.example.livecamera")
  private var sink: FlutterEventSink?
  private var configured = false
  private var targetWidth = 320
  private var frameCounter = 0
  private var lastSent = CFAbsoluteTimeGetCurrent()

  static func register(with registrar: FlutterPluginRegistrar) {
    let camera = LiveCamera()
    let methods = FlutterMethodChannel(
      name: "cipherbird_example/live_camera", binaryMessenger: registrar.messenger)
    methods.setMethodCallHandler(camera.handle)
    let frames = FlutterEventChannel(
      name: "cipherbird_example/live_camera/frames", binaryMessenger: registrar.messenger)
    frames.setStreamHandler(camera)
  }

  private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "start":
      let preset = (call.arguments as? [String: Any])?["preset"] as? String ?? "low"
      AVCaptureDevice.requestAccess(for: .video) { granted in
        DispatchQueue.main.async {
          guard granted else {
            result(FlutterError(code: "denied", message: "camera access was not granted", details: nil))
            return
          }
          do {
            let size = try self.start(preset: preset)
            result(["width": size.0, "height": size.1])
          } catch {
            result(FlutterError(code: "camera", message: error.localizedDescription, details: nil))
          }
        }
      }
    case "stop":
      session.stopRunning()
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func start(preset: String) throws -> (Int, Int) {
    if !configured {
      guard let device = AVCaptureDevice.default(for: .video) else {
        throw NSError(domain: "LiveCamera", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "no camera was found"])
      }
      let input = try AVCaptureDeviceInput(device: device)
      let output = AVCaptureVideoDataOutput()
      output.videoSettings = [
        kCVPixelBufferPixelFormatTypeKey as String:
          kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
      ]
      output.alwaysDiscardsLateVideoFrames = true
      output.setSampleBufferDelegate(self, queue: queue)
      session.beginConfiguration()
      if session.canAddInput(input) { session.addInput(input) }
      if session.canAddOutput(output) { session.addOutput(output) }
      session.commitConfiguration()
      configured = true
    }
    let wanted: [AVCaptureSession.Preset] =
      preset == "high" ? [.hd1280x720, .vga640x480]
      : preset == "medium" ? [.vga640x480, .hd1280x720]
      : [.cif352x288, .vga640x480, .hd1280x720]
    session.beginConfiguration()
    if let usable = wanted.first(where: { session.canSetSessionPreset($0) }) {
      session.sessionPreset = usable
    }
    session.commitConfiguration()
    targetWidth = preset == "high" ? 640 : preset == "medium" ? 480 : 320
    frameCounter = 0
    session.startRunning()
    let dims = CMVideoFormatDescriptionGetDimensions(
      (session.inputs.first as! AVCaptureDeviceInput).device.activeFormat.formatDescription)
    return (Int(dims.width), Int(dims.height))
  }

  func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
    sink = events
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    sink = nil
    return nil
  }

  func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer,
                     from connection: AVCaptureConnection) {
    guard let sink = sink, let pixels = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
    // At most fifteen frames a second reach Dart, and never more than about
    // targetWidth columns: the source is assessed, not displayed in full.
    let now = CFAbsoluteTimeGetCurrent()
    if now - lastSent < 1.0 / 15.0 { return }
    lastSent = now
    CVPixelBufferLockBaseAddress(pixels, .readOnly)
    defer { CVPixelBufferUnlockBaseAddress(pixels, .readOnly) }
    guard let base = CVPixelBufferGetBaseAddressOfPlane(pixels, 0) else { return }
    let fullWidth = CVPixelBufferGetWidthOfPlane(pixels, 0)
    let fullHeight = CVPixelBufferGetHeightOfPlane(pixels, 0)
    let stride = CVPixelBufferGetBytesPerRowOfPlane(pixels, 0)
    let step = max(1, fullWidth / targetWidth)
    let width = fullWidth / step
    let height = fullHeight / step
    var luma = Data(count: width * height)
    luma.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) in
      let out = dst.baseAddress!.assumingMemoryBound(to: UInt8.self)
      let src = base.assumingMemoryBound(to: UInt8.self)
      for row in 0..<height {
        let srcRow = src + row * step * stride
        let dstRow = out + row * width
        if step == 1 {
          memcpy(dstRow, srcRow, width)
        } else {
          for col in 0..<width { dstRow[col] = srcRow[col * step] }
        }
      }
    }
    DispatchQueue.main.async {
      sink(["width": width, "height": height, "luma": FlutterStandardTypedData(bytes: luma)])
    }
  }
}
